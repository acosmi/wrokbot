// Clean-room Electron edge for the Rust-owned engine protocol (v4 §11.2/§11.3).
import { app, BrowserWindow, protocol, session } from "electron";
import net from "node:net";
import { Buffer } from "node:buffer";
import process from "node:process";

import { FRAME_FIXED_HEADER_BYTES, FRAME_HELLO_MAGIC, FRAME_MAGIC, MAX_BOOT_BYTES, MAX_CONTROL_FRAME_BYTES, MAX_IMAGE_BYTES, PROTOCOL, PROTOCOL_VERSION, RELEASE_EPOCH } from "./generated/protocol.mjs";

const BROWSER_SCHEME = "acosmi-engine";
const COMPONENT_SCHEME = "component";
const SCREENCAST = PROTOCOL.screencast;
const VIEWPORT_WIDTH = SCREENCAST.max_width;
const VIEWPORT_HEIGHT = SCREENCAST.max_height;

app.enableSandbox();
protocol.registerSchemesAsPrivileged([
  {
    scheme: BROWSER_SCHEME,
    privileges: { standard: true, secure: true, supportFetchAPI: false, corsEnabled: false },
  },
  {
    scheme: COMPONENT_SCHEME,
    privileges: { standard: true, secure: true, supportFetchAPI: false, corsEnabled: false },
  },
]);

let boot = null, control = null, frame = null, engineSession = null, active = null, lastStopped = null;
let frameSequence = 0n, inputBuffer = Buffer.alloc(0), commandChain = Promise.resolve(), fatalStarted = false;

void bootstrap().catch((error) => fatal(error instanceof EngineFailure ? error.code : "bootstrap_failed"));

async function bootstrap() {
  boot = await readBootCapability();
  control = await connectPipe(boot.control_pipe);
  frame = await connectPipe(boot.frame_pipe);
  frame.write(Buffer.concat([Buffer.from(FRAME_HELLO_MAGIC, "ascii"), Buffer.from(boot.token, "hex")]));
  sendControl(control, { kind: "hello", token: boot.token });
  await app.whenReady();
  engineSession = session.fromPartition(partitionFor(boot));
  await configureSession(engineSession, boot.role);
  const mainMetric = app.getAppMetrics().find((entry) => entry.pid === process.pid);
  if (!(mainMetric?.creationTime > 0)) throw new EngineFailure("main_metric_missing");
  installPipeHandlers();
  sendControl(control, {
    kind: "ready",
    main_pid: process.pid,
    main_creation_time: mainMetric.creationTime,
    protocol_version: PROTOCOL_VERSION,
  });
}

function installPipeHandlers() {
  control.on("data", (chunk) => {
    inputBuffer = Buffer.concat([inputBuffer, chunk]);
    if (inputBuffer.length > MAX_CONTROL_FRAME_BYTES) {
      fatal("control_frame_too_large");
      return;
    }
    while (true) {
      const newline = inputBuffer.indexOf(0x0a);
      if (newline < 0) return;
      const line = inputBuffer.subarray(0, newline);
      inputBuffer = inputBuffer.subarray(newline + 1);
      if (line.length === 0) continue;
      let command;
      try {
        command = parseControlLine(line);
      } catch (_error) {
        fatal("control_frame_invalid");
        return;
      }
      if (command.kind === "frame_ack") {
        void handleFrameAck(command).catch(() => fatal("frame_ack_invalid"));
        continue;
      }
      commandChain = commandChain
        .then(() => handleCommand(command))
        .catch((error) => reportCommandError(command.operation_id, error));
    }
  });
  control.on("close", () => void shutdownEngine(false));
  control.on("error", () => fatal("control_pipe_failed"));
  frame.on("error", () => fatal("frame_pipe_failed"));
}

async function readBootCapability() {
  let bytes = Buffer.alloc(0);
  for await (const chunk of process.stdin) {
    bytes = Buffer.concat([bytes, chunk]);
    if (bytes.length > MAX_BOOT_BYTES) throw new Error("boot_too_large");
    const newline = bytes.indexOf(0x0a);
    if (newline < 0) continue;
    const trailing = bytes.subarray(newline + 1).toString("utf8").trim();
    if (trailing.length !== 0) throw new Error("boot_trailing_data");
    const parsed = JSON.parse(bytes.subarray(0, newline).toString("utf8"));
    validateBoot(parsed);
    return parsed;
  }
  throw new Error("boot_missing");
}

function validateBoot(value) {
  requireExactKeys(value, ["computer_id", "control_pipe", "frame_pipe", "generation", "protocol_version", "release_epoch", "role", "scope_digest", "token"]);
  if (value.protocol_version !== PROTOCOL_VERSION) throw new Error("protocol_mismatch");
  if (value.release_epoch !== String(RELEASE_EPOCH)) throw new Error("release_epoch_mismatch");
  if (!PROTOCOL.roles.includes(value.role)) throw new Error("role_invalid");
  if (!isBoundedString(value.control_pipe, 512) || !isBoundedString(value.frame_pipe, 512)) {
    throw new Error("pipe_invalid");
  }
  if (!isBoundedString(value.computer_id, 256)) throw new Error("computer_invalid");
  if (!/^[0-9]+$/.test(value.generation)) throw new Error("generation_invalid");
  if (!/^[0-9a-f]{64}$/.test(value.scope_digest)) throw new Error("scope_invalid");
  if (!/^[0-9a-f]{32}$/.test(value.token)) throw new Error("token_invalid");
}

function connectPipe(path) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path });
    socket.once("connect", () => resolve(socket)); socket.once("error", reject);
  });
}

function partitionFor(value) {
  if (value.role === "browser_computer") return `persist:ob-${value.scope_digest}`;
  return `ob-component-${value.token}`;
}

async function configureSession(engineSession, role) {
  await engineSession.setProxy({
    mode: "fixed_servers",
    proxyRules: "http=127.0.0.1:1;https=127.0.0.1:1",
    proxyBypassRules: "<-loopback>",
  });
  engineSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  engineSession.setPermissionCheckHandler(() => false);
  engineSession.webRequest.onBeforeRequest((details, callback) => {
    const parsed = new URL(details.url);
    const allowedScheme = role === "browser_computer" ? BROWSER_SCHEME : COMPONENT_SCHEME;
    const allowed =
      parsed.protocol === `${allowedScheme}:` ||
      (role === "sandboxed_component" && ["data:", "blob:"].includes(parsed.protocol));
    callback({ cancel: !allowed });
  });
  const scheme = role === "browser_computer" ? BROWSER_SCHEME : COMPONENT_SCHEME;
  engineSession.protocol.handle(scheme, (request) => internalDocument(request, scheme, role));
}

function internalDocument(request, scheme, role) {
  const parsed = new URL(request.url);
  if (parsed.protocol !== `${scheme}:` || parsed.hostname !== "session") {
    return new Response("", { status: 404 });
  }
  const label = role === "browser_computer" ? "Browser engine ready" : "Component engine ready";
  const html = `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; connect-src 'none'; style-src 'unsafe-inline'; img-src data: blob:"><style>@keyframes pulse{from{background:#175cd3}to{background:#2e90fa}}html,body{margin:0;width:100%;min-height:100%;background:#f4f4f2;color:#202020;font:16px system-ui}#label{position:absolute;left:760px;top:40px}#hover{position:absolute;left:40px;top:40px;width:160px;height:64px;background:#b42318}#hover:hover{animation:pulse 20ms infinite alternate}#press{position:absolute;left:40px;top:136px;width:160px;height:64px;border:0;background:#067647;color:white}#press:active{background:#9333ea}#typing{position:absolute;left:40px;top:232px;width:280px;height:48px;font:28px monospace}#scroll{position:absolute;left:400px;top:40px;width:280px;height:220px;overflow:auto;border:4px solid #202020}#scroll-fill{height:1000px;background:repeating-linear-gradient(#fdb022 0 100px,#7f56d9 100px 200px)}#page-fill{position:absolute;left:760px;top:1400px;width:200px;height:100px;background:#dc6803}</style></head><body><div id="hover"></div><button id="press">Press target</button><input id="typing" aria-label="Typing target" autofocus><div id="scroll"><div id="scroll-fill"></div></div><strong id="label">${label}</strong><div id="page-fill"></div></body></html>`;
  return new Response(html, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}

function parseControlLine(line) {
  const value = JSON.parse(line.toString("utf8"));
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("control_shape");
  }
  if (!PROTOCOL.commands.includes(value.kind)) throw new Error("control_kind");
  return value;
}

async function handleCommand(command) {
  if (!isBoundedString(command.operation_id, 128)) throw new Error("operation_invalid");
  if (command.kind === "shutdown") {
    requireExactKeys(command, ["kind", "operation_id"]);
    await shutdownEngine(true, command.operation_id);
    return;
  }
  validateScope(command);
  if (!isBoundedString(command.tab_id, 256)) throw new Error("tab_invalid");
  if (command.kind !== "input") {
    const extra = command.kind === "screencast" ? ["enabled"] : [];
    requireExactKeys(command, ["computer_id", "generation", "kind", "operation_id", "tab_id", ...extra]);
  }
  if (command.kind === "start") {
    if (active !== null) {
      sendControl(control, { kind: "error", operation_id: command.operation_id, code: "session_busy" });
      return;
    }
    await startSession(command);
    return;
  }
  if (command.kind === "stop" && active === null && lastStopped?.tabId === command.tab_id) {
    sendStopped(command.operation_id, lastStopped, true);
    return;
  }
  if (active === null || active.tabId !== command.tab_id) {
    sendControl(control, { kind: "error", operation_id: command.operation_id, code: "session_stale" });
    return;
  }
  if (command.kind === "input") await applyInput(command);
  else if (command.kind === "stop") await stopSession(command.operation_id);
  else if (command.kind === "screencast") {
    if (typeof command.enabled !== "boolean") throw new EngineFailure("screencast_state_invalid");
    const replayed = await setScreencast(active, command.enabled);
    sendControl(control, { kind: "screencast_state", operation_id: command.operation_id, tab_id: active.tabId, enabled: command.enabled, received_frames: String(active.receivedFrames), acknowledged_frames: String(active.acknowledgedFrames), replayed });
  } else throw new EngineFailure("command_invalid");
}

function validateScope(command) {
  if (command.computer_id !== boot.computer_id || command.generation !== boot.generation) {
    throw new Error("scope_stale");
  }
}

async function startSession(command) {
  const scheme = boot.role === "browser_computer" ? BROWSER_SCHEME : COMPONENT_SCHEME;
  const target = `${scheme}://session/${encodeURIComponent(command.tab_id)}`;
  const window = new BrowserWindow({
    show: false,
    width: VIEWPORT_WIDTH,
    height: VIEWPORT_HEIGHT,
    useContentSize: true,
    backgroundColor: "#f4f4f2",
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      webviewTag: false,
      devTools: false,
      session: engineSession,
    },
  });
  let resolveFirstFrame;
  let rejectFirstFrame;
  const firstFrame = new Promise((resolve, reject) => {
    resolveFirstFrame = resolve;
    rejectFirstFrame = reject;
  });
  active = {
    window,
    tabId: command.tab_id,
    operationId: command.operation_id,
    deviceScaleFactor: 0,
    frameChain: Promise.resolve(),
    pendingAck: null,
    receivedFrames: 0,
    sentFrames: 0,
    acknowledgedFrames: 0,
    resolveFirstFrame,
    rejectFirstFrame,
    firstFrameResolved: false,
    messageHandler: null,
    stopping: false,
    casting: false,
  };
  lastStopped = null;
  const contents = window.webContents;
  contents.setWindowOpenHandler(() => ({ action: "deny" }));
  contents.on("will-navigate", (event, url) => {
    if (url !== target) event.preventDefault();
  });
  contents.on("will-attach-webview", (event) => event.preventDefault());
  contents.on("render-process-gone", (_event, details) => {
    if (active?.operationId === command.operation_id) {
      const reason = ["clean-exit", "abnormal-exit", "killed", "crashed", "oom", "launch-failed", "integrity-failure"].includes(details.reason)
        ? details.reason.replace("-", "_")
        : "unknown";
      sendControl(control, { kind: "error", operation_id: command.operation_id, code: `renderer_gone_${reason}` });
    }
  });
  await withDeadline(window.loadURL(target), "load_timeout");
  contents.debugger.attach("1.3");
  let keepDebugger = false;
  try {
    await withDeadline(contents.debugger.sendCommand("Page.enable"), "page_enable_timeout");
    const probe = await withDeadline(
      contents.debugger.sendCommand("Runtime.evaluate", {
        expression: "({processType:typeof process,requireType:typeof require,origin:location.origin,deviceScaleFactor:window.devicePixelRatio})",
        returnByValue: true,
      }),
      "runtime_probe_timeout",
    );
    const value = probe.result?.value;
    if (value?.processType !== "undefined" || value?.requireType !== "undefined" || !finite(value?.deviceScaleFactor) || value.deviceScaleFactor <= 0) {
      throw new Error("renderer_node_exposed");
    }
    active.deviceScaleFactor = value.deviceScaleFactor;
    active.messageHandler = (_event, method, params) => {
      if (method !== "Page.screencastFrame" || active?.operationId !== command.operation_id) return;
      const current = active;
      current.frameChain = current.frameChain
        .then(() => handleScreencastFrame(current, params))
        .catch((error) => {
          current.rejectFirstFrame(error);
          if (current.firstFrameResolved) reportCommandError(command.operation_id, error);
        });
    };
    await setScreencast(active, true);
    await withDeadline(firstFrame, "screencast_first_frame_timeout");
    const rendererPid = contents.getOSProcessId();
    const metric = app.getAppMetrics().find((entry) => entry.pid === rendererPid);
    const electronSandboxSignal = metric?.sandboxed === true;
    if (!(metric?.creationTime > 0) || (process.platform !== "linux" && !electronSandboxSignal)) {
      throw new EngineFailure("renderer_not_sandboxed");
    }
    sendControl(control, {
      kind: "started",
      operation_id: command.operation_id,
      tab_id: command.tab_id,
      renderer_pid: rendererPid,
      renderer_creation_time: metric.creationTime,
      renderer_sandboxed: electronSandboxSignal,
      node_exposed: false,
      origin: value.origin,
    });
    keepDebugger = true;
  } finally {
    if (!keepDebugger && contents.debugger.isAttached()) contents.debugger.detach();
  }
}

async function applyInput(command) {
  if (!PROTOCOL.input_kinds.includes(command.input_kind)) throw new EngineFailure("input_kind_invalid");
  const current = active;
  if (current === null || current.window.isDestroyed()) throw new EngineFailure("session_stale");
  const common = ["computer_id", "generation", "input_kind", "kind", "operation_id", "tab_id"];
  let dispatch;
  if (["mouse_move", "mouse_down", "mouse_up"].includes(command.input_kind)) {
    requireExactKeys(command, [...common, "button", "click_count", "modifiers", "x", "y"]);
    if (!finite(command.x) || !finite(command.y) || !button(command.button) || !uint32(command.click_count) || !modifiers(command.modifiers)) {
      throw new EngineFailure("input_mouse_invalid");
    }
    const type = command.input_kind === "mouse_move" ? "mouseMoved" : command.input_kind === "mouse_down" ? "mousePressed" : "mouseReleased";
    if ((type === "mouseMoved") !== (command.click_count === 0)) throw new EngineFailure("input_click_count_invalid");
    dispatch = current.window.webContents.debugger.sendCommand("Input.dispatchMouseEvent", { type, x: command.x, y: command.y, button: command.button, clickCount: command.click_count, modifiers: command.modifiers });
  } else if (command.input_kind === "wheel") {
    requireExactKeys(command, [...common, "delta_x", "delta_y", "modifiers", "x", "y"]);
    if (![command.x, command.y, command.delta_x, command.delta_y].every(finite) || !modifiers(command.modifiers)) {
      throw new EngineFailure("input_wheel_invalid");
    }
    dispatch = current.window.webContents.debugger.sendCommand("Input.dispatchMouseEvent", { type: "mouseWheel", x: command.x, y: command.y, deltaX: command.delta_x, deltaY: command.delta_y, modifiers: command.modifiers });
  } else if (["key_down", "raw_key_down", "key_up"].includes(command.input_kind)) {
    const textKeys = command.input_kind === "key_down" ? ["text"] : [];
    requireExactKeys(command, [...common, "code", "key", "modifiers", "native_virtual_key_code", ...textKeys, "windows_virtual_key_code"]);
    if (!isBoundedString(command.key, 4096) || !isBoundedString(command.code, 4096) || !uint32(command.windows_virtual_key_code) || command.native_virtual_key_code !== command.windows_virtual_key_code || !modifiers(command.modifiers)) {
      throw new EngineFailure("input_key_invalid");
    }
    if (command.input_kind === "key_down" && !isBoundedString(command.text, 60000)) throw new EngineFailure("input_text_invalid");
    const type = command.input_kind === "key_down" ? "keyDown" : command.input_kind === "raw_key_down" ? "rawKeyDown" : "keyUp";
    const params = { type, key: command.key, code: command.code, windowsVirtualKeyCode: command.windows_virtual_key_code, nativeVirtualKeyCode: command.native_virtual_key_code, modifiers: command.modifiers };
    if (command.input_kind === "key_down") params.text = command.text;
    dispatch = current.window.webContents.debugger.sendCommand("Input.dispatchKeyEvent", params);
  } else {
    requireExactKeys(command, [...common, "text"]);
    if (!boundedText(command.text, 60000)) throw new EngineFailure("input_text_invalid");
    dispatch = current.window.webContents.debugger.sendCommand("Input.insertText", { text: command.text });
  }
  await withDeadline(dispatch, "input_cdp_timeout");
  sendControl(control, { kind: "input_applied", operation_id: command.operation_id, tab_id: command.tab_id, input_kind: command.input_kind });
}

async function handleScreencastFrame(current, params) {
  if (current.stopping || current.pendingAck !== null) throw new EngineFailure("screencast_ack_window");
  requireExactKeys(params, ["data", "metadata", "sessionId"]);
  if (!params.metadata || typeof params.metadata !== "object" || Array.isArray(params.metadata) || !uint32(params.sessionId)) {
    throw new EngineFailure("screencast_frame_shape");
  }
  const metadata = params.metadata;
  const capturedAtMs = Math.trunc(metadata.timestamp * 1000);
  const width = metadata.deviceWidth;
  const height = metadata.deviceHeight;
  const deviceScaleFactor = Math.fround(current.deviceScaleFactor);
  const pageScaleFactor = Math.fround(metadata.pageScaleFactor);
  const scrollX = Math.fround(metadata.scrollOffsetX);
  const scrollY = Math.fround(metadata.scrollOffsetY);
  if (!Number.isSafeInteger(capturedAtMs) || capturedAtMs <= 0 || !uint32(width) || !uint32(height) || width === 0 || height === 0 || width > VIEWPORT_WIDTH || height > VIEWPORT_HEIGHT || !positiveFloat32(deviceScaleFactor) || !positiveFloat32(pageScaleFactor) || !float32(scrollX) || !float32(scrollY)) {
    throw new EngineFailure("screencast_metadata_invalid");
  }
  const maxBase64 = Math.ceil(MAX_IMAGE_BYTES / 3) * 4 + 4;
  if (typeof params.data !== "string" || params.data.length === 0 || params.data.length > maxBase64) {
    throw new EngineFailure("screencast_data_invalid");
  }
  const image = Buffer.from(params.data, "base64");
  current.receivedFrames = increment(current.receivedFrames);
  await sendFrame(current, image, {
    capturedAtMs,
    width,
    height,
    deviceScaleFactor,
    pageScaleFactor,
    scrollX,
    scrollY,
    screencastSessionId: params.sessionId,
  });
  current.sentFrames = increment(current.sentFrames);
  if (!current.firstFrameResolved) {
    current.firstFrameResolved = true;
    current.resolveFirstFrame();
  }
}

async function handleFrameAck(command) {
  requireExactKeys(command, ["computer_id", "frame_sequence", "generation", "kind", "screencast_session_id", "tab_id"]);
  validateScope(command);
  if (!isBoundedString(command.tab_id, 256) || !canonicalU64(command.frame_sequence) || !uint32(command.screencast_session_id)) {
    throw new EngineFailure("frame_ack_shape");
  }
  const current = active;
  const pending = current?.pendingAck;
  if (current === null || current.tabId !== command.tab_id || pending === null || pending.sequence !== BigInt(command.frame_sequence) || pending.sessionId !== command.screencast_session_id) {
    throw new EngineFailure("frame_ack_stale");
  }
  await withDeadline(current.window.webContents.debugger.sendCommand("Page.screencastFrameAck", { sessionId: pending.sessionId }), "frame_ack_timeout");
  current.acknowledgedFrames = increment(current.acknowledgedFrames);
  current.pendingAck = null;
  pending.resolve();
}

function sendStopped(operationId, stopped, replayed) {
  sendControl(control, {
    kind: "stopped",
    operation_id: operationId,
    tab_id: stopped.tabId,
    received_frames: String(stopped.receivedFrames),
    acknowledged_frames: String(stopped.acknowledgedFrames),
    replayed,
  });
}

async function sendFrame(current, image, metadata) {
  if (image.length === 0 || image.length > MAX_IMAGE_BYTES) throw new Error("frame_size");
  const computer = Buffer.from(boot.computer_id, "utf8");
  const tab = Buffer.from(current.tabId, "utf8");
  if (computer.length > 0xffff || tab.length > 0xffff) throw new Error("frame_id_size");
  const headerLength = FRAME_FIXED_HEADER_BYTES + computer.length + tab.length;
  const header = Buffer.alloc(FRAME_FIXED_HEADER_BYTES);
  header.write(FRAME_MAGIC, 0, "ascii");
  header.writeUInt16LE(PROTOCOL_VERSION, 8);
  header.writeUInt8(boot.role === "browser_computer" ? 0 : 1, 10);
  header.writeUInt8(1, 11);
  header.writeUInt32LE(headerLength, 12);
  header.writeUInt32LE(image.length, 16);
  header.writeBigUInt64LE(BigInt(boot.generation), 20);
  if (frameSequence === 0xffffffffffffffffn) throw new EngineFailure("frame_sequence_exhausted");
  frameSequence += 1n;
  header.writeBigUInt64LE(frameSequence, 28);
  header.writeBigInt64LE(BigInt(metadata.capturedAtMs), 36);
  header.writeUInt32LE(metadata.width, 44);
  header.writeUInt32LE(metadata.height, 48);
  header.writeFloatLE(metadata.deviceScaleFactor, 52);
  header.writeFloatLE(metadata.pageScaleFactor, 56);
  header.writeFloatLE(metadata.scrollX, 60);
  header.writeFloatLE(metadata.scrollY, 64);
  header.writeUInt32LE(metadata.screencastSessionId, 68);
  header.writeUInt16LE(computer.length, 72);
  header.writeUInt16LE(tab.length, 74);
  let resolveAck;
  const ack = new Promise((resolve) => {
    resolveAck = resolve;
  });
  current.pendingAck = { sequence: frameSequence, sessionId: metadata.screencastSessionId, promise: ack, resolve: resolveAck };
  const bytes = Buffer.concat([header, computer, tab, image]);
  const accepted = frame.write(bytes);
  if (!accepted) {
    await new Promise((resolve) => frame.once("drain", resolve));
  }
}

async function setScreencast(current, enabled) {
  if (current.casting === enabled) return true;
  const contents = current.window.webContents;
  if (enabled) {
    contents.debugger.on("message", current.messageHandler);
    await withDeadline(contents.debugger.sendCommand("Page.startScreencast", {
      format: SCREENCAST.format,
      quality: SCREENCAST.quality,
      maxWidth: SCREENCAST.max_width,
      maxHeight: SCREENCAST.max_height,
      everyNthFrame: SCREENCAST.every_nth_frame,
      maxFramesInFlight: SCREENCAST.max_frames_in_flight,
      sendLastFrame: SCREENCAST.send_last_frame,
    }), "screencast_start_timeout");
  } else {
    await withDeadline(contents.debugger.sendCommand("Page.stopScreencast"), "screencast_stop_timeout");
    contents.debugger.off("message", current.messageHandler);
    await withDeadline(current.frameChain, "screencast_frame_drain_timeout");
    if (current.pendingAck !== null) await withDeadline(current.pendingAck.promise, "screencast_ack_drain_timeout");
    if (current.receivedFrames !== current.sentFrames || current.receivedFrames !== current.acknowledgedFrames) {
      throw new EngineFailure("screencast_accounting_invalid");
    }
  }
  current.casting = enabled;
  return false;
}

async function stopSession(operationId) {
  const current = active;
  if (current === null) throw new EngineFailure("session_stale");
  await setScreencast(current, false);
  current.stopping = true;
  active = null;
  lastStopped = {
    tabId: current.tabId,
    receivedFrames: current.receivedFrames,
    acknowledgedFrames: current.acknowledgedFrames,
  };
  destroySession(current);
  sendStopped(operationId, lastStopped, false);
}

async function shutdownEngine(acknowledge, operationId = "connection-closed") {
  if (active !== null) {
    const current = active;
    active = null;
    destroySession(current);
  }
  if (acknowledge) sendControl(control, { kind: "shutdown_complete", operation_id: operationId });
  control.end();
  frame.end();
  app.quit();
}

function sendControl(socket, value) { socket.write(`${JSON.stringify(value)}\n`); }

function destroySession(current) {
  if (current === null || current.window.isDestroyed()) return;
  const contents = current.window.webContents;
  if (current.messageHandler !== null) contents.debugger.off("message", current.messageHandler);
  if (contents.debugger.isAttached()) contents.debugger.detach();
  current.window.destroy();
}

function requireExactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error("keys_invalid");
  }
}

function isBoundedString(value, max) {
  return typeof value === "string" && value.length > 0 && Buffer.byteLength(value, "utf8") <= max;
}

function boundedText(value, max) {
  return typeof value === "string" && Buffer.byteLength(value, "utf8") <= max;
}

function finite(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function uint32(value) {
  return Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
}

function canonicalU64(value) {
  return typeof value === "string" && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= 0xffffffffffffffffn;
}

function float32(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function positiveFloat32(value) {
  return float32(value) && value > 0;
}

function increment(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value === Number.MAX_SAFE_INTEGER) throw new EngineFailure("counter_exhausted");
  return value + 1;
}

function modifiers(value) {
  return Number.isInteger(value) && value >= 0 && value <= 15;
}

function button(value) { return ["left", "right", "middle"].includes(value); }

class EngineFailure extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function withDeadline(promise, code) {
  let timer;
  const deadline = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new EngineFailure(code)), 5000);
  });
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

function reportCommandError(operationId, error) {
  const code = error instanceof EngineFailure ? error.code : "command_failed";
  sendControl(control, { kind: "error", operation_id: operationId, code });
  const current = active;
  active = null;
  destroySession(current);
}

function fatal(code) {
  if (fatalStarted) return;
  fatalStarted = true;
  const current = active;
  active = null;
  destroySession(current);
  process.exitCode = 1;
  const exit = () => {
    if (frame !== null && !frame.destroyed) frame.end();
    app.exit(1);
  };
  if (control !== null && !control.destroyed) {
    control.write(`${JSON.stringify({ kind: "error", code })}\n`, exit);
    setTimeout(exit, 250);
  } else {
    exit();
  }
}

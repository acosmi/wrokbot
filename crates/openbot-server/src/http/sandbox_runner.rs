//! Network-navigated opaque sandbox bootstrap with a per-response CSP nonce.

use axum::body::Body;
use axum::response::Response;
use http::StatusCode;
use http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY};
use openbot_contracts::error::AppError;
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::HttpError;

/// Fixed CSP prefix around one response-random nonce.
pub const SANDBOX_CSP_PREFIX: &str = "default-src 'none'; connect-src 'none'; script-src 'nonce-";
/// Fixed CSP suffix; authored CSS and only data/blob images are deliberate exceptions.
pub const SANDBOX_CSP_SUFFIX: &str = "'; style-src 'unsafe-inline'; img-src data: blob:";

const SANDBOX_RUNNER_JS: &str = r#""use strict";
(()=>{
  const bootstrap=document.currentScript;
  const nonce=bootstrap?.nonce||"";
  if(!nonce||location.hash.length<2||location.hash.length>2097153)return;
  bootstrap.nonce="";
  bootstrap.removeAttribute("nonce");
  bootstrap.remove();
  let payload;
  try{
    const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const raw=location.hash.slice(1);
    let bits=0,buffer=0;
    const bytes=[];
    for(const character of raw){
      const value=alphabet.indexOf(character);
      if(value<0)throw new Error("invalid base64url");
      buffer=(buffer<<6)|value;
      bits+=6;
      if(bits>=8){bits-=8;bytes.push((buffer>>bits)&255);}
    }
    let text="";
    for(let index=0;index<bytes.length;){
      const first=bytes[index++];
      let point;
      if(first<128){point=first;}
      else if(first>=194&&first<=223){
        const second=bytes[index++];
        if((second&192)!==128)throw new Error("invalid utf8");
        point=((first&31)<<6)|(second&63);
      }else if(first>=224&&first<=239){
        const second=bytes[index++],third=bytes[index++];
        if((second&192)!==128||(third&192)!==128||
           (first===224&&second<160)||(first===237&&second>=160))throw new Error("invalid utf8");
        point=((first&15)<<12)|((second&63)<<6)|(third&63);
      }else if(first>=240&&first<=244){
        const second=bytes[index++],third=bytes[index++],fourth=bytes[index++];
        if((second&192)!==128||(third&192)!==128||(fourth&192)!==128||
           (first===240&&second<144)||(first===244&&second>=144))throw new Error("invalid utf8");
        point=((first&7)<<18)|((second&63)<<12)|((third&63)<<6)|(fourth&63);
      }else{throw new Error("invalid utf8");}
      if(point<=65535){text+=String.fromCharCode(point);}
      else{point-=65536;text+=String.fromCharCode(55296+(point>>10),56320+(point&1023));}
    }
    payload=JSON.parse(text);
    try{history.replaceState(null,"",location.pathname);}catch(_error){}
  }catch(_error){return;}
  if(!payload||Array.isArray(payload)||typeof payload!=="object"||
     Object.keys(payload).sort().join(",")!=="arguments,capability,css,html,jsFunctions"||
     !/^[0-9a-f]{64}$/.test(payload.capability)||
     typeof payload.html!=="string"||typeof payload.css!=="string"||
     typeof payload.jsFunctions!=="string"||!payload.arguments||
     Array.isArray(payload.arguments)||typeof payload.arguments!=="object")return;
  const receive=(event)=>{
    if(event.data!=="openbot_sandbox_init:"+payload.capability)return;
    const port=event.ports[0];
    if(!port)return;
    window.onmessage=null;
    let failed=false;
    const send=(kind)=>{port.postMessage(kind+":"+payload.capability);port.close();};
    const previousOnError=window.onerror;
    window.onerror=()=>{failed=true;return true;};
    try{
      document.body.style.margin="0";
      const style=document.createElement("style");
      style.textContent=payload.css;
      document.head.append(style);
      document.getElementById("openbot-sandbox-root").innerHTML=payload.html;
      window.__args=payload.arguments;
      const user=document.createElement("script");
      user.nonce=nonce;
      user.textContent="document.currentScript.nonce='';document.currentScript.removeAttribute('nonce');\n"+payload.jsFunctions;
      document.body.append(user);
    }catch(_error){failed=true;}
    window.onerror=previousOnError;
    send(failed?"failed":"ready");
  };
  window.onmessage=receive;
})();
"#;

/// `GET /sandbox/runner`; ordinary navigation avoids inheriting the parent page's CSP container.
pub async fn document() -> Result<Response<Body>, HttpError> {
    let nonce = random_nonce()?;
    let csp = format!("{SANDBOX_CSP_PREFIX}{nonce}{SANDBOX_CSP_SUFFIX}");
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"></head><body><div id=\"openbot-sandbox-root\"></div><script nonce=\"{nonce}\">{SANDBOX_RUNNER_JS}</script></body></html>"
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .header(CACHE_CONTROL, "no-store")
        .header(CONTENT_SECURITY_POLICY, csp)
        .header(REFERRER_POLICY, "no-referrer")
        .body(Body::from(body))
        .map_err(|_| application_contract_error())
}

fn random_nonce() -> Result<String, HttpError> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| AppError::DependencyUnavailable {
            dependency: "system_random",
        })?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn application_contract_error() -> HttpError {
    AppError::DependencyUnavailable {
        dependency: "sandbox_runner",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;

    use super::*;

    #[tokio::test]
    async fn runner_nonce_is_fresh_csp_is_exact_and_bootstrap_is_single_wrapped_script() {
        let first = document().await.unwrap();
        let second = document().await.unwrap();
        let first_csp = first.headers()[CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .to_owned();
        let second_csp = second.headers()[CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(first_csp.starts_with(SANDBOX_CSP_PREFIX));
        assert!(first_csp.ends_with(SANDBOX_CSP_SUFFIX));
        assert_ne!(first_csp, second_csp);
        let nonce = first_csp
            .strip_prefix(SANDBOX_CSP_PREFIX)
            .unwrap()
            .strip_suffix(SANDBOX_CSP_SUFFIX)
            .unwrap()
            .to_owned();
        assert_eq!(nonce.len(), 64);
        assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let body = to_bytes(first.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(body.matches("<script ").count(), 1);
        assert!(body.contains(&format!("<script nonce=\"{nonce}\">")));
        assert!(body.contains("window.__args=payload.arguments"));
        assert!(
            body.find("window.__args=payload.arguments").unwrap()
                < body.find("user.textContent=").unwrap()
        );
        assert!(body.contains("document.currentScript.nonce=''"));
        assert!(!SANDBOX_RUNNER_JS.contains("</script"));
        assert!(!SANDBOX_RUNNER_JS.contains("fetch("));
        assert!(!SANDBOX_RUNNER_JS.contains("XMLHttpRequest"));
        assert!(!SANDBOX_RUNNER_JS.contains("atob("));
        assert!(!SANDBOX_RUNNER_JS.contains("TextDecoder"));
    }
}

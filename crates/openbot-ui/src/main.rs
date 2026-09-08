//! Browser entry point for the shared Server Web/Desktop WebView bundle.

#[cfg(target_arch = "wasm32")]
fn main() {
    openbot_ui::mount();
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {}

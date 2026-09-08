//! Neutral decorative artwork shared by computer waiting surfaces.

use leptos::prelude::*;

const ART_VIEW_BOX: &str = "0 0 1200 800";
const ART_PRESERVE_ASPECT_RATIO: &str = "xMidYMid meet";

/// Render the first-source neutral line drawing without gradients, filters or remote assets.
#[component]
pub fn ComputerPlaceholderArt() -> impl IntoView {
    view! {
        <svg
            class="ob-computer-placeholder-art"
            viewBox=ART_VIEW_BOX
            preserveAspectRatio=ART_PRESERVE_ASPECT_RATIO
            fill="none"
            stroke="currentColor"
            stroke-width="8"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
            focusable="false"
            data-art="computer-placeholder"
        >
            <rect class="ob-computer-art-frame" x="140" y="110" width="920" height="580" rx="32"></rect>
            <path d="M140 210H1060"></path>
            <circle cx="200" cy="160" r="12"></circle>
            <circle cx="248" cy="160" r="12"></circle>
            <circle cx="296" cy="160" r="12"></circle>
            <path d="M360 210V690"></path>
            <rect x="190" y="270" width="120" height="28" rx="14"></rect>
            <rect x="190" y="334" width="120" height="28" rx="14"></rect>
            <rect x="190" y="398" width="120" height="28" rx="14"></rect>
            <rect x="190" y="590" width="120" height="44" rx="22"></rect>
            <rect x="430" y="280" width="560" height="160" rx="24"></rect>
            <path d="M478 330H770"></path>
            <path d="M478 382H892"></path>
            <rect x="430" y="500" width="252" height="120" rx="24"></rect>
            <rect x="738" y="500" width="252" height="120" rx="24"></rect>
            <path d="M478 548H620"></path>
            <path d="M786 548H928"></path>
        </svg>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn art_geometry_is_one_fixed_id_free_coordinate_system() {
        assert_eq!(ART_VIEW_BOX, "0 0 1200 800");
        assert_eq!(ART_PRESERVE_ASPECT_RATIO, "xMidYMid meet");
    }
}

#!/bin/bash

# Shield Branding Assets Generator
# Generates all required logo variations from source image

set -e  # Exit on any error

# Configuration
SOURCE_IMAGE="source_logo_2000x2000.png"
OUTPUT_DIR="branding-assets"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if source image exists
check_source() {
    if [ ! -f "$SOURCE_IMAGE" ]; then
        log_error "Source image '$SOURCE_IMAGE' not found!"
        log_info "Please ensure the image exists in the current directory"
        exit 1
    fi
    log_success "Source image found: $SOURCE_IMAGE"
}

# Create directory structure
create_directories() {
    log_info "Creating directory structure..."

    directories=(
        "$OUTPUT_DIR/01-master"
        "$OUTPUT_DIR/02-github"
        "$OUTPUT_DIR/03-social"
        "$OUTPUT_DIR/04-web"
        "$OUTPUT_DIR/05-favicon"
        "$OUTPUT_DIR/06-future"
    )

    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
    done

    log_success "Directory structure created"
}

# Generate image with specific parameters
generate_image() {
    local filename=$1
    local width=$2
    local height=$3
    local bg_type=$4  # "transparent" or "white"
    local output_path=$5

    log_info "Generating $filename (${width}x${height}px)..."

    # Base scaling filter
    local filter="scale=${width}:${height}:force_original_aspect_ratio=decrease"

    # Add background if needed
    if [ "$bg_type" = "white" ]; then
        filter="${filter},pad=${width}:${height}:(ow-iw)/2:(oh-ih)/2:white"
    else
        filter="${filter},pad=${width}:${height}:(ow-iw)/2:(oh-ih)/2:color=0x00000000"
    fi

    # Execute ffmpeg command
    if ffmpeg -i "$SOURCE_IMAGE" -vf "$filter" -y "$output_path" 2>/dev/null; then
        log_success "Created $filename"
    else
        log_error "Failed to create $filename"
        return 1
    fi
}

# Generate horizontal logo layout
generate_horizontal() {
    local filename=$1
    local width=$2
    local height=$3
    local output_path=$4

    log_info "Generating horizontal $filename (${width}x${height}px)..."

    local filter="scale=${width}:${height}:force_original_aspect_ratio=decrease,pad=${width}:${height}:(ow-iw)/2:(oh-ih)/2:color=0x00000000"

    if ffmpeg -i "$SOURCE_IMAGE" -vf "$filter" -y "$output_path" 2>/dev/null; then
        log_success "Created horizontal $filename"
    else
        log_error "Failed to create horizontal $filename"
        return 1
    fi
}

# Generate SVG (convert from PNG)
generate_svg() {
    local svg_path="$OUTPUT_DIR/01-master/logo-vector.svg"
    local png_source="$OUTPUT_DIR/01-master/logo-master-2000px.png"

    log_info "Generating SVG from master PNG..."

    cat > "$svg_path" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<svg width="2000" height="2000" viewBox="0 0 2000 2000" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <title>Shield - EXPTIME-Secure Encryption</title>
  <image width="2000" height="2000" xlink:href="data:image/png;base64,$(base64 -w 0 "$png_source")" />
</svg>
EOF

    if [ -f "$svg_path" ]; then
        log_success "Created SVG vector logo"
    else
        log_error "Failed to create SVG"
        return 1
    fi
}

# Generate ICO favicon
generate_ico() {
    local ico_path="$OUTPUT_DIR/05-favicon/favicon.ico"
    local png_16="$OUTPUT_DIR/05-favicon/favicon-16px.png"
    local png_32="$OUTPUT_DIR/05-favicon/favicon-32px.png"

    log_info "Generating ICO favicon..."

    if command -v convert >/dev/null 2>&1; then
        convert "$png_16" "$png_32" "$ico_path" 2>/dev/null
        log_success "Created ICO favicon"
    else
        log_warning "ImageMagick not found, skipping ICO generation"
    fi
}

# Phase 1: Essential Assets
generate_phase1() {
    log_info "=== PHASE 1: ESSENTIAL ASSETS ==="

    # Master file
    generate_image "logo-master-2000px.png" 2000 2000 "transparent" "$OUTPUT_DIR/01-master/logo-master-2000px.png"

    # GitHub avatar
    generate_image "logo-github-420px.png" 420 420 "transparent" "$OUTPUT_DIR/02-github/logo-github-420px.png"

    # Favicon
    generate_image "favicon-32px.png" 32 32 "transparent" "$OUTPUT_DIR/05-favicon/favicon-32px.png"
    generate_image "favicon-16px.png" 16 16 "transparent" "$OUTPUT_DIR/05-favicon/favicon-16px.png"

    # SVG (depends on master PNG)
    generate_svg

    log_success "Phase 1 complete!"
}

# Phase 2: Social Media Assets
generate_phase2() {
    log_info "=== PHASE 2: SOCIAL MEDIA ASSETS ==="

    # Social media profiles
    generate_image "logo-social-400px.png" 400 400 "transparent" "$OUTPUT_DIR/03-social/logo-social-400px.png"
    generate_image "logo-facebook-170px.png" 170 170 "transparent" "$OUTPUT_DIR/03-social/logo-facebook-170px.png"

    # Social sharing cards
    generate_image "social-sharing-1200px.png" 1200 630 "white" "$OUTPUT_DIR/02-github/social-sharing-1200px.png"
    generate_image "social-sharing-1200px-wide.png" 1200 600 "white" "$OUTPUT_DIR/03-social/social-sharing-1200px-wide.png"

    # Horizontal layouts for web
    generate_horizontal "logo-horizontal-800px.png" 800 200 "$OUTPUT_DIR/04-web/logo-horizontal-800px.png"
    generate_horizontal "logo-horizontal-600px.png" 600 150 "$OUTPUT_DIR/04-web/logo-horizontal-600px.png"
    generate_horizontal "logo-horizontal-400px.png" 400 100 "$OUTPUT_DIR/04-web/logo-horizontal-400px.png"

    log_success "Phase 2 complete!"
}

# Phase 3: Advanced Assets
generate_phase3() {
    log_info "=== PHASE 3: ADVANCED ASSETS ==="

    # App icons
    generate_image "app-icon-1024px.png" 1024 1024 "transparent" "$OUTPUT_DIR/06-future/app-icon-1024px.png"
    generate_image "app-icon-512px.png" 512 512 "transparent" "$OUTPUT_DIR/06-future/app-icon-512px.png"

    # Thumbnails
    generate_image "card-thumbnail-200px.png" 200 200 "transparent" "$OUTPUT_DIR/04-web/card-thumbnail-200px.png"

    # README logo (512px for GitHub display)
    generate_image "logo-readme-512px.png" 512 512 "transparent" "$OUTPUT_DIR/02-github/logo-readme-512px.png"

    # Generate ICO favicon
    generate_ico

    log_success "Phase 3 complete!"
}

# Generate summary report
generate_report() {
    log_info "=== GENERATION REPORT ==="

    echo ""
    echo "Generated files in $OUTPUT_DIR:"
    find "$OUTPUT_DIR" -type f | sort | while read file; do
        size=$(du -h "$file" | cut -f1)
        echo "  ${file#$OUTPUT_DIR/} ($size)"
    done

    echo ""
    echo "Summary:"
    echo "  Total files: $(find "$OUTPUT_DIR" -type f | wc -l)"
    echo "  Total size: $(du -sh "$OUTPUT_DIR" | cut -f1)"
    echo ""
    echo "Ready to use! Shield branding assets are complete."
}

# Main execution
main() {
    echo "Shield Branding Assets Generator"
    echo "================================="
    echo ""

    check_source
    create_directories

    generate_phase1
    generate_phase2
    generate_phase3

    generate_report

    log_success "All Shield branding assets generated successfully!"
}

main "$@"

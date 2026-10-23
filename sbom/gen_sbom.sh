# Generate the SBOMs using debsbom 0.10.2.
DEBSBOM="docker run --rm -i ghcr.io/siemens/debsbom@sha256:1d11fddfc747a59835c85c958f6a617f0d427fbad059fa59009c0e656b2d5313 debsbom"

gen_sbom() {
    name=$1
    img=$2

    echo "Generating the SBOM of $img with debsbom..."
    # The digest refers to images for several architectures. The SBOMs
    # describe the arm64 image.
    crt=$(docker create --platform linux/arm64 "$img")
    docker export "$crt" | $DEBSBOM generate -t spdx --root - -o - \
        > "sbom/$name.spdx.json"
    docker rm -f "$crt" > /dev/null

    echo "Generating the SBOM graph of $img with debsbom.."
    $DEBSBOM export -t spdx - - < "sbom/$name.spdx.json" \
        > "sbom/$name.graphml"
}

# Generate SBOMs for the first images published for each release.
gen_sbom debian-bullseye-20210816 \
    debian@sha256:38988bd08d1a5534ae90bea146e199e2b7a8fca334e9a7afe5297a7c919e96ea
gen_sbom debian-bookworm-20230612 \
    debian@sha256:d568e251e460295a8743e9d5ef7de673c5a8f9027db11f4e666e96fb5bed708e
gen_sbom debian-trixie-20250811 \
    debian@sha256:6d87375016340817ac2391e670971725a9981cfc24e221c47734681ed0f6c0f5

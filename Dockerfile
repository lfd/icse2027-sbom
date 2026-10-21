FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS tool

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

RUN apt-get update && apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    ca-certificates \
    curl \
    git \
    make \
    vim \
    cloc \
    cppcheck

# Create virtual environment and install build backend.
RUN python3 -m venv /venv
ENV VIRTUAL_ENV=/venv
ENV PATH="/venv/bin:$PATH"

RUN pip install --upgrade pip
RUN pip install hatchling

# Install sbom-analysis tool.
COPY ./src /app
COPY README.md /app
COPY pyproject.toml /app

WORKDIR /app
RUN pip install -e .

# Install R and LaTeX packages for plot and table generation.
FROM tool AS full

RUN apt-get update && apt-get install -y \
    r-base \
    r-base-dev \
    libpng-dev \
    r-cran-cowplot \
    r-cran-dplyr \
    r-cran-ggplot2 \
    r-cran-ggrepel \
    r-cran-igraph \
    r-cran-jsonlite \
    r-cran-optparse \
    r-cran-patchwork \
    r-cran-scales \
    r-cran-tidyr \
    r-cran-xml2 \
    r-cran-yaml \
    texlive-luatex \
    texlive-latex-base \
    texlive-latex-recommended \
    texlive-latex-extra \
    texlive-pictures \
    texlive-fonts-recommended \
    texlive-fonts-extra \
    && rm -rf /var/lib/apt/lists/*

# Packages not available from Debian Trixie are installed from CRAN.
RUN Rscript -e 'install.packages(c("this.path", "ggnetwork", "ggh4x", \
    "tikzDevice"), repos = "https://cloud.r-project.org")'

# Fail the build rather than a single script if a package of the plot scripts
# is missing.
RUN Rscript -e 'for (p in c("cowplot", "dplyr", "ggh4x", "ggnetwork", \
    "ggplot2", "ggrepel", "igraph", "jsonlite", "optparse", "patchwork", \
    "this.path", "tidyr", "tikzDevice", "xml2", "yaml")) \
    library(p, character.only = TRUE)'

WORKDIR /work

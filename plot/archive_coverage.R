# Generate an overview of repository types in the Debian Sources index to
# evaluate coverage statistics in a CSV table.
Sys.setenv(LANG = "en")
Sys.setenv(TZ = "UTC")

library(dplyr)
library(optparse)
library(ggplot2)
library(scales)
library(this.path)

setwd(this.path::here())
source("layout.R", chdir = TRUE)
create_save_locations()


opt <- parse_args(OptionParser(option_list = list(
  make_option("--sources", type = "character", default = "",
              help = "Sources index to read, xz compressed or plain"),
  make_option("--release", type = "character", default = "",
              help = "Release it belongs to, which names the output")
)))


# Repositories of hosts and services that were retired in favour of Salsa.
retired <- c("anonscm.debian.org", "git.debian.org", "alioth.debian.org")

#' Parse the sources file and scan the Vcs-Git and Homepage field of package.
#'
#' @param file the Sources index, xz compressed or plain.
#' @return one row per source package.
#'
read_sources_index <- function(file) {
  con <- if (endsWith(file, ".xz")) xzfile(file, "rt") else file(file, "rt")
  lines <- readLines(con, warn = FALSE)
  close(con)

  # The index is a large text file with paragraphs, one per source package.
  # Therefore, we assign fields to the last observed package name.
  keep <- startsWith(lines, "Package: ") |
    startsWith(lines, "Vcs-Git: ") | startsWith(lines, "Homepage: ")
  lines <- lines[keep]
  field <- sub(":.*", "", lines)
  value <- trimws(sub("^[^:]+:", "", lines))
  package <- ifelse(field == "Package", value, NA_character_)
  package <- package[cummax(seq_along(package) * !is.na(package))]

  fields <- data.frame(package = package, field = field, value = value) %>%
    filter(field != "Package") %>%
    # A Vcs-Git field may name a branch behind the URL.
    mutate(value = sub(" .*", "", value)) %>%
    distinct(package, field, .keep_all = TRUE) %>%
    tidyr::pivot_wider(names_from = field, values_from = value)

  data.frame(package = unique(value[field == "Package"])) %>%
    left_join(fields, by = "package") %>%
    rename(vcs_git = "Vcs-Git", homepage = "Homepage")
}


# Analyse the sources index.
if (!file.exists(opt$sources)) {
  stop(sprintf("No Sources index at %s.", opt$sources))
}
index <- read_sources_index(opt$sources)

index <- index %>%
  mutate(host = sub("/.*", "", sub("^[a-z+]+://", "", vcs_git)),
         host = sub(".*@", "", sub(":.*", "", host)),
         repo = sub("\\.git$", "", sub("/$", "", vcs_git)))

# Summarise package repository statistics.
n <- nrow(index)
shared <- index %>% filter(!is.na(repo)) %>% count(repo, name = "packages")
largest <- shared %>% arrange(desc(packages))

summary_tbl <- tibble::tribble(
  ~quantity,
  ~packages,
  "Source packages", n,
  "With Vcs-Git", sum(!is.na(index$vcs_git)),
  "Vcs-Git on salsa.debian.org", sum(index$host == "salsa.debian.org",
                                     na.rm = TRUE),
  "Vcs-Git on retired host", sum(index$host %in% retired, na.rm = TRUE),
  "No Vcs-Git, but homepage", sum(is.na(index$vcs_git) &
                                      !is.na(index$homepage)),
  "Neither Vcs-Git nor homepage", sum(is.na(index$vcs_git) &
                                        is.na(index$homepage)),
  "Packages in mono repos", sum(shared$packages[shared$packages > 1]),
  sprintf("Packages in %s", basename(largest$repo[1])), largest$packages[1]
) %>%
  mutate(share = packages / n) %>%
  # Add summary scores.
  bind_rows(tibble::tribble(
    ~quantity, ~packages,
    "Repositories", nrow(shared),
    "Mono repositories", sum(shared$packages > 1)
  ))

# Store table.
write.csv(summary_tbl,
          file.path(OUTDIR_CSV, sprintf("archive_%s.csv", opt$release)),
          row.names = FALSE)

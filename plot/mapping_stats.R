# Summarises how the verified repository links in the package mapping were
# identified correctly for the first time: resolved by the tool (scraping),
# proposed by an AI model, or determined manually.
Sys.setenv(LANG = "en")
Sys.setenv(TZ = "UTC")

library(dplyr)
library(jsonlite)
library(optparse)
library(this.path)
library(yaml)

setwd(this.path::here())
source("layout.R", chdir = TRUE)
create_save_locations()

opt <- parse_args(OptionParser(option_list = list(
  make_option("--model_conf", type = "character",
              default = "conf/model.yml",
              help = paste("Model configuration, relative to the repository",
                           "root. The releases follow from it")),
  make_option("--mapping", type = "character",
              default = "src/sbom_analysis/resources/package_mapping.json",
              help = "Package mapping, relative to the repository root"),
  make_option("--all", action = "store_true", default = FALSE,
              help = "Describe every entry of the mapping, not only the releases")
)))

mapping <- jsonlite::fromJSON(file.path(ROOT, opt$mapping),
                              simplifyVector = FALSE)

# The packages of the analysed releases, by name as the mapping keys them.
inputs <- model_inputs(opt$model_conf)
packages_per_release <- lapply(inputs$conf_files, function(f) {
  yaml::read_yaml(f)$packages
})
names(packages_per_release) <- inputs$releases

# Determine distinct package names across releases and ensure that all
# package names are matched.
names_per_release <- lapply(packages_per_release, function(packages) {
  unique(vapply(packages, `[[`, "", "name"))
})
release_names <- unique(unlist(names_per_release))
release_packages <- sum(lengths(packages_per_release))
if (!opt$all) {
  mapping <- mapping[intersect(names(mapping), release_names)]
}

# Groups to show in the statistics, with a human-readable label for each.
SOURCES <- c(scraping = "Resolved by scraping",
             ai = "Proposed by AI",
             manual = "Determined manually",
             unknown = "Unknown source")
ORIGINS <- c(SOURCES, absent = "Confirmed absent", unverified = "Not verified")

origin_of <- function(entry, side) {
  url <- entry[[side]]
  verified <- isTRUE(entry[[paste0(side, "_verified")]])
  source <- entry[[paste0(side, "_source")]]
  if (!verified) {
    return("unverified")
  }
  if (is.null(url) || nchar(url) == 0) {
    return("absent")
  }
  if (is.null(source) || !(source %in% names(SOURCES))) {
    return("unknown")
  }
  source
}

# Restrict the package mapping to the package names of the analysed releases.
links <- bind_rows(lapply(names(mapping), function(package) {
  data.frame(package = package,
             side = c("downstream", "upstream"),
             origin = c(origin_of(mapping[[package]], "downstream"),
                        origin_of(mapping[[package]], "upstream")),
             stringsAsFactors = FALSE)
}))

# Aggregate the package mapping stats.
stats <- links %>%
  mutate(origin = factor(origin, levels = names(ORIGINS))) %>%
  count(side, origin, .drop = FALSE) %>%
  tidyr::pivot_wider(names_from = side, values_from = n, values_fill = 0) %>%
  mutate(origin = ORIGINS[as.character(origin)],
         # Share of the downstream and upstream repositories that was resolved
         # automatically.
         downstream_share = downstream / length(mapping),
         upstream_share = upstream / length(mapping),
         # Number of unique package names.
         package_names = length(mapping),
         # Number of SBOM entries covered by these packages across releases,
         # counting once per release.
         packages = if (opt$all) NA_integer_ else release_packages)

write.csv(stats, file.path(OUTDIR_CSV, "mapping_stats.csv"), row.names = FALSE)

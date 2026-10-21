# Generate the release table with descriptive statistics on package resolution
# and coverage, and a supplementary table with repository hosts.
Sys.setenv(LANG = "en")
Sys.setenv(TZ = "UTC")

library(dplyr)
library(optparse)
library(this.path)

setwd(this.path::here())
source("layout.R", chdir = TRUE)
create_save_locations()

opt <- parse_args(OptionParser(option_list = list(
  make_option("--model_conf", type = "character",
              default = "conf/model.yml",
              help = paste("Model configuration file"))
)))

#' Describe one release.
#'
#' @param windows the package windows of every release.
#' @param conf_file the release configuration file.
#' @param release the name to report the release.
#' @return the aggregated stats.
#'
describe_release <- function(windows, conf_file, release) {
  conf <- yaml::read_yaml(conf_file)

  # Count different packages with at least one repository in the config.
  set <- function(x) !is.null(x) && nchar(x) > 0
  resolved <- vapply(conf$packages, function(p) {
    set(p$downstream_repo) || set(p$upstream_repo)
  }, logical(1))

  # Check whether a specific field is present in the config.
  has <- function(field) {
    vapply(conf$packages, function(p) set(p[[field]]), logical(1))
  }
  # Count packages with the given field, e.g. repository or directory.
  traced <- function(field) sum(has(field))
  # Count packages with the given field and a version checkout.
  matched <- function(side, field = paste0(side, "_repo")) {
    sum(has(field) & has(paste0(side, "_checkout")))
  }

  # Select the package windows of the release and mark whether they are
  # affected by a severe vulnerability.
  observed <- windows[windows$release == release, ] %>%
    mutate(severe = critical_osv_count + high_osv_count > 0)

  # Combine the package windows of one release into one row per package,
  # evaluating whether any of its windows is affected by a severe
  # vulnerability.
  per_package <- observed %>%
    group_by(package_id) %>%
    summarise(combination = first(combination), severe = any(severe),
              .groups = "drop")

  # Mark the source packages to count them separately from the binary packages.
  sources <- vapply(conf$packages, function(p) {
    grepl("arch=source", p$package_url, fixed = TRUE)
  }, logical(1))

  # Create the summary data frame with the release statistics on resolved
  # packages, traced repositories and directories, matched versions, and
  # the number of analysed packages and affected units.
  nonempty <- function(x) length(unique(x[!is.na(x) & nchar(x) > 0]))
  data.frame(
    release = release,
    packages = length(conf$packages),
    source = sum(sources),
    binary = sum(!sources),
    resolved = sum(resolved),
    with_downstream = traced("downstream_repo"),
    with_upstream = traced("upstream_repo"),
    in_directory = traced("downstream_path"),
    downstream_versions = matched("downstream"),
    upstream_versions = matched("upstream"),
    directory_versions = matched("downstream", "downstream_path"),
    analysed = nrow(per_package),
    downstream = nonempty(observed$downstream_url),
    upstream = nonempty(observed$upstream_url),
    directories = nonempty(observed$downstream_path),
    units = n_distinct(per_package$combination),
    affected = n_distinct(per_package$combination[per_package$severe])
  )
}

#' Count the repositories of one release per host.
#'
#' @param conf_file the release configuration.
#' @param release the name to report the release under.
#' @param field the repository field of a package.
#' @return one row per host, with the distinct repositories.
#'
repository_hosts <- function(conf_file, release, field) {
  conf <- yaml::read_yaml(conf_file)

  # Get the repository URLs of the packages.
  urls <- vapply(conf$packages, function(p) {
    if (is.null(p[[field]])) "" else p[[field]]
  }, "")

  # Determine the host of each repository URL.
  host <- sub("^www\\.", "", sub("[:/].*$", "",
                                 sub("^([a-z+]+://)?([^@/]+@)?", "", urls)))

  # Merge Savannah aliases.
  host[host %in% c("git.sv.gnu.org", "https.git.savannah.gnu.org",
                   "git.savannah.nongnu.org")] <- "git.savannah.gnu.org"
  host[urls == ""] <- "none"

  # Count the distinct repositories and the packages per host.
  data.frame(release = release, host = host,
             repo = sub("(\\.git)?/?$", "", urls)) %>%
    group_by(release, host) %>%
    summarise(repositories = if (host[1] == "none") 0L else n_distinct(repo),
              packages = n(), .groups = "drop") %>%
    arrange(desc(packages))
}

inputs <- model_inputs(opt$model_conf)
windows <- read_metrics(inputs)

# Summarise the releases with descriptive statistics.
stats <- bind_rows(mapply(describe_release, inputs$conf_files,
                          levels(windows$release),
                          MoreArgs = list(windows = windows),
                          SIMPLIFY = FALSE))
write.csv(stats, file.path(OUTDIR_CSV, "release_stats.csv"), row.names = FALSE)

# Format the release statistics table for LaTeX.
# The columns follow the pipeline, separated by vertical lines between SBOM
# package types, traced repositories, matched versions and analysis units for
# the empirical evaluation.
columns <- c(release = "Release", packages = "Packages", source = "Source",
             binary = "Binary", resolved = "Resolved",
             with_downstream = "Downstream", in_directory = "Directory",
             with_upstream = "Upstream",
             downstream_versions = "Down. version",
             directory_versions = "Dir. version",
             upstream_versions = "Up. version", analysed = "Analysed",
             units = "Units", affected = "Affected")
cells <- lapply(names(columns), function(column) {
  if (column == "release") stats[[column]] else fmt(stats[[column]])
})
write_table(
  rows = do.call(paste, c(cells, sep = " & ")),
  header = unname(columns),
  align = "lrrr|rrrr|rrr|rrr",
  save_path = file.path(OUTDIR_TAB, "release_stats.tex"),
  rotate = TRUE,
  # Narrower spacing to fit all columns into the width of a column.
  colsep = "2.1pt"
)

# Summarise hosts of the downstream and upstream repositories.
for (side in c("downstream", "upstream")) {
  hosts <- bind_rows(mapply(repository_hosts, inputs$conf_files,
                            levels(windows$release),
                            MoreArgs = list(field = paste0(side, "_repo")),
                            SIMPLIFY = FALSE))
  write.csv(hosts, file.path(OUTDIR_CSV, paste0(side, "_hosts.csv")),
            row.names = FALSE)
}

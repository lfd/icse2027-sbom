INCH.PER.CM <- 1/2.54
TEXTWIDTH <- 18.13275*INCH.PER.CM
COLWIDTH <- 8.85553*INCH.PER.CM
HEIGHT <- 23.61475*INCH.PER.CM
BASE.SIZE <- 8.5
SMALL.SIZE <- 7.5
TINY.SIZE <- 6.5 #
TABLE.FONT.SIZE <- 2 #
SYM.SIZE <- 1.2 # Symbol size in legends
LINE.SIZE <- 0.6 # 1
LINE.SIZE.THIN <- 0.3
POINT.SIZE <- 0.5
BIG.POINT.SIZE <- 0.8

# New LfD colours.
COLOURS.LIST.DARK <- c("#c88b0c", "#818181", "#508c82", "#8271a1", "#bb615a", "#4f7c97")
COLOURS.LIST.MEDIUM <- c("#ead3aa", "#d1d1d1", "#b5dad4", "#d5cbeb", "#f3c4bf", "#bdd5e6")
COLOURS.LIST.LIGHT <- c("#f8ecd3", "#e8e8e8", "#d8eeeb", "#e5dff3", "#ffdbd8", "#dae8f3")
OUTDIR_TIKZ <- "./tex/"
OUTDIR_PDF <- "./pdf/"
OUTDIR_CSV <- "./csv/"
OUTDIR_TAB <- "./tab/"
ROOT <- ".."

# How a metric is named in a figure. A spelled out name takes more room than
# the cells or bars it labels, and the same metric has to read the same way
# in every figure, so the names live here rather than in one script.
METRIC.LABELS <- c(project_age = "Project age",
                   version_age = "Version age",
                   commits = "Commits",
                   commit_trend = "Commit trend",
                   developers = "Developers",
                   contributor_trend = "Contributor trend",
                   pony_factor = "Pony factor",
                   core_stayer_ratio = "Core stayer ratio",
                   core_leaver_ratio = "Core leaver ratio",
                   stayer_ratio = "Stayer ratio",
                   leaver_ratio = "Leaver ratio",
                   newcomer_ratio = "Newcomer ratio",
                   bot_ratio = "Bot ratio",
                   corrective_ratio = "Corrective ratio",
                   churn_per_function = "Churn/Func.",
                   function_growth = "Function growth",
                   loc = "LOC",
                   files = "Files",
                   cyclomatic_complexity_per_function = "CyC/Func.",
                   tokens_per_function = "Tokens/Func.",
                   critical_osv_count = "Critical OSVs",
                   severe_osv = "Severely vuln.",
                   total_osv_count = "OSVs, any severity")

#' Name a metric for a figure.
#'
#' @param name the column name.
#' @return the label, the column spelled out where it has no short name.
#'
label_of <- function(name) {
  if (name %in% names(METRIC.LABELS)) {
    METRIC.LABELS[[name]]
  } else {
    sub("^(.)", "\\U\\1", gsub("_", " ", name), perl = TRUE)
  }
}

#' Resolve the inputs of a fitted model.
#'
#' @param conf_file the model configuration, relative to the repository root.
#' @param root the repository root.
#' @return the model details.
#'
model_inputs <- function(conf_file = "conf/model.yml", root = ROOT) {
  conf <- yaml::read_yaml(file.path(root, conf_file))
  metrics <- vapply(conf$conf_files, function(f) {
    release <- yaml::read_yaml(file.path(root, f))
    file.path(root, release$analysis_dir, "metrics.csv")
  }, "")
  model_dir <- if (is.null(conf$model_dir)) "data/model" else conf$model_dir
  base <- file.path(root, model_dir, conf$name)
  list(name = conf$name,
       releases = conf$releases,
       conf_files = file.path(root, conf$conf_files),
       features = conf$features,
       severities = conf$severities,
       metrics_files = unname(metrics),
       coefficients = paste0(base, "_coefficients.csv"),
       data = paste0(base, "_data.csv"))
}

#' Format a number for a LaTeX table.
#'
#' @param x the value.
#' @param digits the number of decimal places.
#' @return the formatted value, or a dash if it is missing.
#'
fmt <- function(x, digits = 0) {
  ifelse(is.na(x), "--",
         formatC(x, format = "f", digits = digits, big.mark = ","))
}

#' Write a table the paper can input, as a tabularray environment.
#'
#' @param rows the formatted rows, without the trailing separator.
#' @param header the column titles.
#' @param align the tabularray column specification.
#' @param save_path where to write it.
#' @param rotate whether to rotate the headings.
#' @param colsep the space on either side of a column.
#' @return nothing; the table is written to save_path.
#'
write_table <- function(rows, header, align, save_path, rotate = FALSE,
                        colsep = "2.9pt") {
  if (rotate) {
    header <- c(header[1], sprintf("\\rotatebox{90}{%s}", header[-1]))
  }
  writeLines(c(
    sprintf("  \\begin{tblr}{colspec={%s},", align),
    sprintf("                colsep=%s,rowsep=0.6pt,", colsep),
    "                row{odd}={bg=gray!15},",
    "                row{1}={bg=white,fg=black}}",
    "        \\toprule",
    paste0("        ", paste(header, collapse = " & "), " \\\\ \\midrule"),
    paste0("        ", rows, " \\\\"),
    "        \\bottomrule",
    "  \\end{tblr}"
  ), save_path)
}

#' Read the observed package windows of every release a model was fitted on.
#'
#' @param inputs what model_inputs() returned.
#' @return one row per package and window, with the release it belongs to
#'   and the combination it is analysed as: both repositories and, where a
#'   packaging repository holds several packages side by side, the directory.
#'
read_metrics <- function(inputs) {
  releases <- sub("^(.)", "\\U\\1", inputs$releases, perl = TRUE)
  data <- dplyr::bind_rows(mapply(function(file, release) {
    metrics <- read.csv(file, stringsAsFactors = FALSE)
    if (!"downstream_path" %in% names(metrics)) {
      metrics$downstream_path <- NA_character_
    }
    metrics <- metrics[!is.na(metrics$project_age), ]
    metrics$release <- release
    metrics
  }, inputs$metrics_files, releases, SIMPLIFY = FALSE))
  data$release <- factor(data$release, levels = releases)
  data$combination <- paste(
    ifelse(is.na(data$downstream_url), "", data$downstream_url),
    ifelse(is.na(data$upstream_url), "", data$upstream_url),
    ifelse(is.na(data$downstream_path), "", data$downstream_path),
    sep = "|")
  data
}

#' Colour the releases.
#'
#' @param releases the release names.
#' @return one colour per release, named by it.
#'
release_colours <- function(releases) {
  setNames(COLOURS.LIST.DARK[c(1, 5, 4)][seq_along(releases)], releases)
}

theme_paper_base <- function() {
  return(theme_bw(base_size=BASE.SIZE) +
           theme(axis.title.x = element_text(size = BASE.SIZE),
                 axis.title.y = element_text(size = BASE.SIZE),
                 legend.title = element_text(size = BASE.SIZE),
                 legend.position = "top",
                 plot.margin = unit(c(0,0.1,0,0.1), 'cm')))
}

shrink_legend <- function(boxc=-5) {
  return(theme(legend.margin=margin(0,0,0,0),
               legend.box.margin=margin(boxc,boxc,boxc,boxc)))
}

#' Write a plot as a PDF and optionally as a TikZ picture.
#'
#' @param plot the plot.
#' @param name the file name without an extension.
#' @param width the width in inches, the text width by default.
#' @param height the height in inches.
#' @param tikz whether to write the TikZ version as well.
#'
save_plot <- function(plot, name, width = TEXTWIDTH, height = 0.6 * TEXTWIDTH,
                      tikz = TRUE) {
  ggplot2::ggsave(file.path(OUTDIR_PDF, paste0(name, ".pdf")), plot = plot,
                  width = width, height = height, units = "in")

  if (!tikz) {
    return(invisible(NULL))
  }

  if (!requireNamespace("tikzDevice", quietly = TRUE)) {
    warning("tikzDevice is not installed, writing the PDF only")
    return(invisible(NULL))
  }

  # Optimise the line width and encode special characters.
  previous <- options(tikzLwdUnit = 72.27 / 96,
                      tikzSanitizeCharacters = c("<", ">"),
                      tikzReplacementCharacters = c("$<$", "$>$"))
  on.exit(options(previous), add = TRUE)

  tikzDevice::tikz(file.path(OUTDIR_TIKZ, paste0(name, ".tex")),
                   width = width, height = height, sanitize = TRUE)
  print(plot)
  grDevices::dev.off()
  invisible(NULL)
}

#' Create the output directories.
#'
create_save_locations <- function() {
  for (d in c(OUTDIR_PDF, OUTDIR_TIKZ, OUTDIR_CSV, OUTDIR_TAB)) {
    if (!dir.exists(d)) {
      dir.create(d, recursive = TRUE)
    }
  }
}



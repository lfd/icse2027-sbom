# Plot the performance of different package attention indicators in terms of
# their ability to prioritize packages with severe vulnerabilities.
Sys.setenv(LANG = "en")
Sys.setenv(TZ = "UTC")

library(dplyr)
library(ggplot2)
library(this.path)

setwd(this.path::here())
source("layout.R", chdir = TRUE)
create_save_locations()

# The releases to compare.
releases <- c(Bookworm = "debian-bookworm-20230612",
              Trixie = "debian-trixie-20250811")

# Number k of packages a reviewer could realistically review, for the
# comparison table.
budgets <- c(10, 20, 30)

# Share of all packages reviewed, marked in the figure as in effort-aware
# defect prediction (Kamei et al., 2013).
effort_share <- 0.2

# Order of the review approaches.
orders <- c(Rule = "rule", Score = "score", Random = "random")
order_colours <- setNames(COLOURS.LIST.DARK[c(4, 1, 2)], names(orders))

#' Get packages and their attention scores from all indicators of one release.
#'
#' @param dir the analysis directory of the release.
#' @param release the name of the release.
#' @return one row per package, with true target, score and indicator.
#'
read_release <- function(dir, release) {
  annotated <- function(name) {
    read.csv(file.path(ROOT, "data", "analysis", dir,
                       paste0("graph_annotated_", name, ".csv")),
             stringsAsFactors = FALSE)
  }
  inner_join(
    annotated(paste0("attention-score-", tolower(release))) %>%
      select(package_id, severe, score = attention_score),
    annotated("rule") %>% select(package_id, rule_rank = rank),
    by = "package_id"
  ) %>%
    mutate(release = release)
}

#' Order packages in review order.
#'
#' @param release the rows of one release.
#' @param order the name of the order.
#' @return the true targets of the packages.
#'
reviewed <- function(release, order) {
  switch(order,
         rule = release$severe[order(release$rule_rank)],
         score = release$severe[order(-release$score)])
}

#' Determine the share of actually affected packages found after each
# 'reviewed package.
#'
#' @param release the rows of one release.
#' @return one row per order and number of reviewed packages, starting at 0.
#'
gain_curves <- function(release) {
  n <- nrow(release)
  affected <- sum(release$severe)
  curves <- lapply(names(orders), function(name) {
    if (orders[[name]] == "random") {
      # Without an indicator providing a review order, every reviewed package
      # finds the same share on average.
      return(data.frame(order = name, reviewed = 0:n, found = (0:n) / n))
    }
    found <- cumsum(reviewed(release, orders[[name]])) / affected
    data.frame(order = name, reviewed = 0:n, found = c(0, found))
  })
  bind_rows(curves) %>% mutate(release = release$release[1])
}

# Merge releases into one table.
rows <- bind_rows(mapply(read_release, releases, names(releases),
                         SIMPLIFY = FALSE))
releases <- names(releases)

# Build the per-release curves.
curves <- bind_rows(lapply(releases, function(r) {
  gain_curves(rows[rows$release == r, ])
})) %>%
  mutate(order = factor(order, levels = names(orders)),
         release = factor(release, levels = releases))

# Review effort of the given share of each release's packages.
effort <- rows %>%
  count(release) %>%
  mutate(reviewed = ceiling(effort_share * n),
         release = factor(release, levels = releases))

# Plot and store the curves for both releases.
p <- ggplot(curves, aes(x = reviewed, y = found, colour = order,
                        linetype = order)) +
  geom_vline(data = effort, aes(xintercept = reviewed),
             colour = COLOURS.LIST.DARK[2], linewidth = LINE.SIZE.THIN,
             linetype = "dotted") +
  geom_step(aes(linewidth = order)) +
  facet_wrap(~release, scales = "free_x") +
  scale_colour_manual(values = order_colours, name = NULL) +
  scale_linetype_manual(values = c(Rule = "solid", Score = "solid",
                                   Random = "dashed"),
                        name = NULL) +
  # Add random baseline.
  scale_linewidth_manual(values = c(Rule = LINE.SIZE, Score = LINE.SIZE,
                                    Random = LINE.SIZE.THIN),
                         name = NULL) +
  scale_y_continuous(limits = c(0, 1), expand = expansion(add = 0.02)) +
  scale_x_continuous(breaks = function(limits) {
                       packages <- floor(limits[2])
                       step <- if (packages < 80) 10 else 25
                       regular <- seq(0, packages, by = step)
                       c(regular[regular <= packages - step / 2], packages)
                     },
                     labels = function(breaks) {
                       packages <- max(breaks, na.rm = TRUE)
                       ifelse(breaks == packages | packages < 80 |
                                breaks %% 50 == 0, breaks, "")
                     },
                     expand = expansion(add = 0.5)) +
  labs(x = "Packages reviewed", y = "Share of affected packages") +
  theme_paper_base() +
  theme(axis.text = element_text(size = SMALL.SIZE),
        axis.title.x = element_text(size = SMALL.SIZE),
        axis.title.y = element_text(size = SMALL.SIZE),
        strip.text = element_text(size = SMALL.SIZE),
        legend.text = element_text(size = TINY.SIZE),
        legend.key.width = unit(0.9 * SYM.SIZE, "line"),
        legend.key.height = unit(0.5 * SYM.SIZE, "line"),
        panel.grid.minor = element_blank(),
        panel.spacing.x = unit(10, "pt"),
        plot.margin = unit(c(0.15, 0.35, 0, 0.1), "cm")) +
  shrink_legend()

save_plot(p, "ranking", width = COLWIDTH,
          height = 0.4 * COLWIDTH)

# Store table with exact numbers a reviewer would find after reviewing k
# packages.
found_within <- bind_rows(lapply(releases, function(r) {
  release <- rows[rows$release == r, ]
  release_budgets <- c(budgets, ceiling(effort_share * nrow(release)))
  bind_rows(lapply(release_budgets, function(k) {
    k <- min(k, nrow(release))
    counts <- vapply(orders[orders != "random"], function(order) {
      sum(head(reviewed(release, order), k))
    }, 0)
    data.frame(release = r, reviewed = k, packages = nrow(release),
               affected = sum(release$severe),
               random = round(k * sum(release$severe) / nrow(release), 1),
               t(counts))
  }))
}))
names(found_within) <- tolower(names(found_within))
write.csv(found_within,
          file.path(OUTDIR_CSV, "ranking.csv"),
          row.names = FALSE)

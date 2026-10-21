# Generate a supplementary metric distribution summary table.
Sys.setenv(LANG = "en")
Sys.setenv(TZ = "UTC")

library(dplyr)
library(tidyr)
library(this.path)

setwd(this.path::here())
source("layout.R", chdir = TRUE)
create_save_locations()

windows <- read_metrics(model_inputs())

# The columns which identify a window rather than describe it.
identifiers <- c("package_name", "package_id", "version", "downstream_url",
                 "upstream_url", "downstream_path", "downstream_checkout",
                 "upstream_checkout", "downstream_primary_lang",
                 "upstream_primary_lang", "window", "window_start",
                 "window_end", "release", "combination")
metrics <- setdiff(names(windows)[vapply(windows, is.numeric, TRUE)],
                   identifiers)

# Calculate descriptive statistics of each metric's distribution.
summary <- windows %>%
  select(release, all_of(metrics)) %>%
  pivot_longer(-release, names_to = "metric", values_to = "value") %>%
  filter(!is.na(value)) %>%
  group_by(release, metric) %>%
  summarise(windows = n(),
            zero = round(mean(value == 0), 3),
            min = min(value),
            q1 = quantile(value, 0.25),
            median = median(value),
            mean = round(mean(value), 3),
            q3 = quantile(value, 0.75),
            max = max(value),
            .groups = "drop") %>%
  mutate(metric = factor(metric, levels = metrics)) %>%
  arrange(metric, release)

write.csv(summary, file.path(OUTDIR_CSV, "metric_summary.csv"),
          row.names = FALSE)

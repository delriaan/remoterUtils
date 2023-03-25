gen_pass <- function(glyphs = "@$", length = NULL, raw = FALSE, chatty = FALSE){
#' Generate a Password
#'
#' \code{gen_pass} creates a password consisting of alphanumeric glyphs and symbols
#'
#' @param glyphs Character-coercibles to use in the creation of the password: this is combined with the output of \code{\link[sodium]{keygen}}
#' @param length (int) The length of the password in character format
#' @param raw (logical) Should the output be returned as raw?
#' @param chatty (logical) Should diagnostic information be provided?
#'
#' @note The generated string always begins with a letter before being returned as-is or returned as a raw vector
#' @export

	set.seed(Sys.time());

  force(glyphs);

  glyphs <- { c(sodium::keygen(), LETTERS, glyphs) |>
      stringi::stri_extract_all_regex(".", simplify = TRUE) |>
      as.vector() |>
      purrr::keep(~.x != "") |>
      table()
    }

  .sample_wgt <- c(.75, 1, .5);

  sample_glyphs <- purrr::as_mapper(~{
    .this <- { ifelse(
        grepl("[0-9A-Z]", names(.x))
        , .x * .sample_wgt[1]
        , ifelse(
            grepl("[a-z]", names(.x))
            , .x * .sample_wgt[2]
            , .x * .sample_wgt[3]
            )) * (3/.x)
      } |>
      ceiling() |>
      purrr::imap(~rep.int(.y, .x)) |>
      unlist(use.names = FALSE);

    sample(
      x = .this
      , size = ifelse(rlang::is_empty(length), length(.this), length)
      , replace = TRUE
      , prob = c(table(.this))[.this]
      ) |>
      paste(collapse = "") |>
      stringi::stri_extract_all_regex(pattern = ".", simplify = TRUE) |>
      as.vector();
  });

  .out <- sample_glyphs(glyphs);
  .alpha_r <- sum(.out %in% letters) / length(.out);
  .ALPHA_r <- sum(.out %in% LETTERS) / length(.out);
  .alpha_ratio <- abs(.alpha_r - .ALPHA_r);

  .iter <- 0;

  while((.alpha_ratio > .10) & (.iter < 1000L)){
    set.seed(sample(.Random.seed, 1));

    .out <- sample_glyphs(glyphs);
    .alpha_r <- sum(.out %in% letters) / length(.out);
    .ALPHA_r <- sum(.out %in% LETTERS) / length(.out);
    .ALPHA_r <- sum(.out %in% LETTERS) / length(.out);
    .alpha_ratio <- abs(.alpha_r - .ALPHA_r);
    .iter <- .iter + 1
  }

  if (chatty){ message(glue::glue("\nPassword generated with replication \ntries: {.iter}\nalpha_ratio:{.alpha_ratio}")) }

  .out <- paste(c(sample(c(letters,LETTERS), 1), .out), collapse = "");

  if (raw){ charToRaw(.out) } else { .out }
}

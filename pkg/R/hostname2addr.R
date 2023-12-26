hostname2addr <- function(addr, ipver = 4){
#' Get the IP Address from a Hostname
#'
#' \code{hostname2addr} pings \code{hostname} and parses the response to get the address.
#'
#' @note Designed for Windows OS
#'
#' @param addr (string) The hostname: if an IP address, the function serves as a form of address accessibility
#' @param ipver (integer | 4) The IP protocol version to use (only version 4 is supported by \code{remoter})
#'
#' @references \href{https://en.wikipedia.org/wiki/IPv6#Address_representation}{IPv6 Addressing (Wikipedia)}
#'
#' @export

  # Capture the IP address from the ping response:
  ip_addr <- suppressWarnings(system2(
    command = "ping"
    , args = glue::glue("{addr} -n 1 -{ipver}")
    , stdout = TRUE
    , stderr = TRUE
    ));

  invalid_ip <- !rlang::is_empty(attributes(ip_addr));

  # Return NULL if an error occurred:
  if (invalid_ip){
    message("No IP address found for ", addr, ": returning NULL ... ");
    invisible(NULL);
  } else {
  # Parse the IP address from the ping response and return the IP address:
    ip_pattern <- ifelse(
      ipver == 4
      , "([0-9]{1,3}[.]){3}[0-9]{1,3}"
      , "fe80[a-z0-9:\\%]+[a-z0-9]"
      );

    stringi::stri_extract_first_regex(ip_addr, ip_pattern) |>
      na.omit() |> unique();
  }
}

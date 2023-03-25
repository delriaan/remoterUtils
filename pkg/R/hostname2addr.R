hostname2addr <- function(addr, ipver = 4){
#' Get the IP Address from a Hostname
#'
#' \code{hostname2addr} pings \code{hostname} and parses the response to get the address
#'
#' @param addr (string) The hostname: if an IP address, the function serves as a form of address accessibility
#' @param ipver (integer | 4) The IP protocol version to use
#'
#' @export

  system2(command = "ping", args = c(addr,glue::glue("-n 1 -{ipver}")), stdout = TRUE) |>
    stringi::stri_extract_first_regex("([0-9]{1,3}[.]){3}[0-9]{1,3}") |>
    na.omit() |> unique()
}

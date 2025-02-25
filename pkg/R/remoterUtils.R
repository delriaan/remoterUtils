#' @title Utility Functions for \code{remoter}
#'
#' @description
#' Package \code{remoterUtils} provides utility functions facilitating management of \code{remoter} sessions as well as authentication objects (see \code{\link[remoter]{remoter-package}} for \code{remoter} documentation).
#' 
#' @section GitHub Dependencies:
#' \enumerate{
#' \item{remotes::install_github("wrathematics/argon2")}
#' \item{remotes::install_github("RBigData/remoter")}
#' }
#'
#' @importFrom stats na.omit
#' @importFrom rlang :=
#' @importFrom book.of.utilities gen.pass
#' @import magrittr
#' @name remoterUtils
NULL

search <- function(){
  #' Override \code{search()}
  #'
  #' This function overrides the default \code{\link[base]{search}} function to allow for use in \href{https://github.com/RBigData/remoter}{remoter} sessions.
  #'
  #' @family Overrides
  #' @export
  res <- base::search();
  res[!res == "zMQ.config"]
}

searchpaths <- function(){
  #' Override \code{searchpaths()}
  #'
  #' This function overrides the default \code{\link[base]{searchpaths}} function for use in \href{https://github.com/RBigData/remoter}{remoter} sessions.
  #' @family Overrides
  #' @export
  res <- base::searchpaths();
  res[!res == "zMQ.config"]
}

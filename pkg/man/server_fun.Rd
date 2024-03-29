% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/server_fun.R
\name{server_fun}
\alias{server_fun}
\title{Manage a \code{remoter} Session}
\usage{
server_fun(
  auth_root = path.expand("~"),
  server_dir = "~",
  session = make.names(tolower(Sys.getenv("COMPUTERNAME"))),
  ...
)
}
\arguments{
\item{auth_root}{The path to the authentication objects to read ('.rdata' files) containing the ciphers and decryption keys.  These should be generated from \code{\link{make_cipher}}}

\item{server_dir}{The path to the working directory for the spawned server}

\item{session}{(string) The session prefix for the ciphers loaded from \code{auth_root}}

\item{...}{\code{\link[rlang]{dots_list}}: additional arguments passed externally}
}
\description{
\code{server_fun} starts or stops a \code{remoter} session (see \code{\link[remoter]{remoter-package}} for documentation).
}
\note{
Designed for Windows OS
}

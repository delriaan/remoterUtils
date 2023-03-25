make.batch_file <- function(server_dir, auth_root, batch.file_name = "start_Rserver.bat", source.file_name = "Rserve.R", session = make.names(tolower(Sys.getenv("COMPUTERNAME")))){
#' Make a \code{remoter} Server Batch File
#'
#' \code{make.batch_file} creates the Windows OS batch file and associated R script to launch the \code{remoter} server.  Existing contents in \code{server_dir} are deleted before repopulating.
#'
#' @param server_dir (string) The server working directory
#' @param auth_root (string) The path to the authentication objects
#' @param batch.file_name (string) The name of the batch file to be created in \code{server_dir}
#' @param source.file_name (string) The name of the R source file to be created in \code{server_dir}
#' @param session (string) The session label for the spawned server: must match the cipher object that is ultimately loaded
#'
#'
#'
#' @return \code{source.file_name} and \code{batch.file_name} (which calls \code{source.file_name}) created in \code{server_dir}
#'
#' @export

  if (missing(server_dir)){
    server_dir <- if (interactive()){
      tcltk::tk_choose.dir(default = path.expand("~"), caption = "Select destination directory for Rserver control files:")
    } else { path.expand("~") }
  }

  if (missing(auth_root)){
    auth_root <- if (interactive()){
      tcltk::tk_choose.dir(default = path.expand("~"), caption = "Select source directory for Rserver authentication files:")
    } else { path.expand("~") }
  }

  if (!dir.exists(server_dir)){
    pass <- dir.create(server_dir)

    if (pass){
      glue::glue("Created {server_dir}") |> message()
    } else {
      stop(glue::glue("Failed to create {server_dir}"))
    }
  }

  purrr::walk(dir(server_dir, full.names = TRUE), unlink);

  # https://superuser.com/questions/149951/does-in-batch-file-mean-all-command-line-arguments
  cat(glue::glue("@echo off\nRscript -e \"source('{server_dir}/{source.file_name}')\" --args %%*")
      , file = paste(server_dir, batch.file_name, sep = "/")
      , append = FALSE
      );

  cat(glue::glue("library(remoterUtils); \nserver_fun(auth_root = \"{auth_root}\", server_dir = \"{server_dir}\", session = \"{session}\", !!!commandArgs(trailingOnly = TRUE))")
      , file = paste(server_dir, source.file_name, sep = "/")
      , append = FALSE
      );
}

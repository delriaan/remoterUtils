make_batch_file <- function(server_dir, auth_root = server_dir, batch.file_name = "start_Rserver.bat", source.file_name = "Rserve.R", session = make.names(hostname())){
  #' Make a \code{remoter} Server Batch File
  #'
  #' \code{make_batch_file} creates the Windows OS batch file and associated R script to launch the \code{remoter} server.  Existing contents in \code{server_dir} are deleted before repopulating.
  #'
  #' @param server_dir (string) The server working directory
  #' @param auth_root (string) The path to the authentication objects
  #' @param batch.file_name (string) The name of the batch file to be created in \code{server_dir}
  #' @param source.file_name (string) The name of the R source file to be created in \code{server_dir}
  #' @param session (string) The session label for the spawned server: must match the cipher object that is ultimately loaded
  #'
  #'
  #' @note Designed for Windows OS
  #'
  #' @return \code{source.file_name} and \code{batch.file_name} (which calls \code{source.file_name}) created in \code{server_dir}
  #'
  #' @export

  # :: Filesystem checks and operations: 
    if (missing(server_dir)){
      server_dir <- if (interactive()){
          choose.dir(default = path.expand("~"), caption = "Select destination directory for Rserver control files:")
        } else { 
          path.expand("~") 
        }
    }

    if (missing(auth_root)){
      auth_root <- server_dir
    }

    if (!dir.exists(server_dir)){
      pass <- fs::dir_create(server_dir)

      if (!rlang::is_empty(pass)){
        glue::glue("Created server directory '{server_dir}'") |> cli::alert_info()
      } else {
        cli::cli_abort(glue::glue("Failed to create server directory '{server_dir}'"))
      }
    }

    if (!dir.exists(auth_root)){
      pass <- fs::dir_create(auth_root)

      if (!rlang::is_empty(pass)){
        glue::glue("Created auth root directory '{auth_root}'") |> cli::alert_info()
      } else {
        cli::cli_abort(glue::glue("Failed to create auth root directory '{auth_root}'"))
      }
    }

    purrr::walk(dir(server_dir, full.names = TRUE), unlink);
  
  # :: Write control files to directories:
    # https://superuser.com/questions/149951/does-in-batch-file-mean-all-command-line-arguments
    glue::glue("@echo off\nRscript -e \"source('{server_dir}/{source.file_name}')\" --vanilla --args %%*") |>
      cat(file = file.path(server_dir, batch.file_name), append = FALSE, sep = "\n")

    glue::glue(
      "library(remoterUtils);"
      , ". <- ifelse(grepl(\"Windows\", osVersion), \"D:\\{server_dir}\", \"/mnt/d/{server_dir}\")"
      , "\n\nserver_fun(auth_root = ., server_dir = ., session = \"{session}\", !!!commandArgs(trailingOnly = TRUE))\n"
      , .sep = "\n"
      ) |>
      cat(file = file.path(server_dir, source.file_name), append = FALSE, sep = "\n")
}

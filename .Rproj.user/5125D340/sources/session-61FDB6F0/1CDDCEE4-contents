# Reference: https://superuser.com/questions/149951/does-in-batch-file-mean-all-command-line-arguments
make_batch_file <- function(server_dir = "~", file.name = "start_Rserver.bat", sessOpts = c("z_host", Sys.getenv("COMPUTERNAME") |> make.names() |> tolower())){
  server_dir <- tcltk::tk_choose.dir(default = server_dir, caption = "Select destination directory for Rserver control files:");
  cat(sprintf('@echo off\nRscript -e \"source(\\"%sRserve.R\\")\" --args %%*', server_dir), file = paste0(server_dir,"/start_Rserver.bat"));

  # REPLACE THE FOLLOWING WITH A PARAMETERIZED SCRIPT, OR MAKE SUCH A SEPARATE FUNCTION
  cat(c("library(remoterUtils);"
        , sprintf("server_fun(server_dir = \"%s\", sessOpts = c(\"z_host\", Sys.getenv(\"COMPUTERNAME\") |> make.names() |> tolower()))", server_dir)
        )
      , sep = "\n"
      , file = paste0(server_dir, "/Rserve.R")
      , append = FALSE
      );
}

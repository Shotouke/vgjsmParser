crear_dataframe <- function(doc, cpe ="Microsoft" ) {
  max <- length(obtenerTodosCPEs(doc))

  df <- data.frame(cve = character(max),
             cpe = character(max),
             cvss = numeric(max))

  df <-lapply(df, as.character)

  cves <- obtenerCVEs(xmlFile)

  longcves <- length(cves)

  listNodes <- xmlToList(doc)

  contadordf <- 1
  for (i in 1:longcves) {
    print("OBTENIENDO CPES")
    cpes <- obtenerCPEbyCVE(listNodes,cves[[i]])
    print(length(cpes))
    print("OBTENIENDO CVSS")
    cvss <- obtenerCVSSbyCVE(listNodes,cves[[i]])

    longcpes <-length(cpes)
    if (longcpes >0) {
      c<-grep(cpe,cpes,ignore.case = T, value = T)

      #lenght(c)

      for (j in 1:longcpes) {
      df$cve[contadordf] <- cves[[i]]
      df$cpe[contadordf] <-cpes[[j]]
      df$cvss[contadordf] <-cvss[[1]]

      contadordf <- contadordf + 1
      }
    }
  }

  return(df)
}

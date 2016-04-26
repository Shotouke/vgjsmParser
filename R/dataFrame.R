crear_dataframe <- function(doc, cpe ="Microsoft" ) {
  max <- length(obtenerTodosCPEs(doc))

  #df <- lapply(data.frame(cve = character(max), cpe = character(max), cvss = numeric(max)), as.character)
  df<-data.frame(cve = character(max), cpe = character(max), cvss = numeric(max), ano = character(max))
  df$cve <- as.character(df$cve)
  df$cpe <- as.character(df$cpe)
  df$ano <- as.character(df$ano)

  cves <- obtenerCVEs(xmlFile)

  longcves <- length(cves)

  listNodes <- xmlToList(doc)

  contadordf <- 1
  for (i in 1:longcves) {
    cpes <- obtenerCPEbyCVE(listNodes,cves[[i]])
    cvss <- obtenerCVSSbyCVE(listNodes,cves[[i]])

    c<-grep(cpe,cpes,ignore.case = T, value = T)
    #longcpes <-length(cpes)
    longcpes <-length(c)

    if (longcpes >0) {
      for (j in 1:longcpes) {
        #df$cve[contadordf] <- cves[[i]]
        #df$cpe[contadordf] <-cpes[[j]]
        #df$cvss[contadordf] <-cvss[[1]]
        df[contadordf,1] <- cves[[i]]
        #df[contadordf,2] <- cpes[[j]]
        df[contadordf,2] <- c[[j]]
        df[contadordf,3] <- cvss[[1]]
        df[contadordf,4] <- substr(cves[[1]],5,8)
        contadordf <- contadordf + 1
      }
    }
  }

  return(df)
}

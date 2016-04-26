crear_dataframe <- function(...) {
  max <- 0
  for (x in list(...)) {
    max <- max + length(obtenerTodosCPEs(x))
  }

  df<-data.frame(cve = character(max), cpe = character(max), cvss = numeric(max), ano = character(max))

  df$cve <- as.character(df$cve)
  df$cpe <- as.character(df$cpe)
  df$ano <- as.character(df$ano)

  return(df)
}

obtenerUlimoElemento <- function(df) {
  longcve <- length(df$cve)
  encontrado <- FALSE
  pos <- 1
  while (pos <= longcve && !encontrado) {
    if (df$cve[[pos]]=="")
      encontrado <- TRUE
    else
      pos <- pos + 1
  }
  return(pos)
}

crear_contenido <- function(xmlFile, listNodes, df, cpe ="Microsoft" ) {

  cves <- obtenerCVEs(xmlFile)

  longcves <- length(cves)

  contadordf <- obtenerUlimoElemento(df)
  for (i in 1:longcves) {
    cpes <- obtenerCPEbyCVE(listNodes,cves[[i]])
    cvss <- obtenerCVSSbyCVE(listNodes,cves[[i]])

    c<-grep(paste("cpe:/o:",cpe,sep=""),cpes,ignore.case = T, value = T)
    longcpes <-length(c)

    if (longcpes >0) {
      for (j in 1:longcpes) {
        df[contadordf,1] <- cves[[i]]
        df[contadordf,2] <- c[[j]]
        df[contadordf,3] <- cvss[[1]]
        df[contadordf,4] <- substr(cves[[1]],5,8)
        contadordf <- contadordf + 1
      }
    }
  }

  return(df)
}

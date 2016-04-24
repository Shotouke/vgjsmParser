crear_dataframe <- function(doc ) {
  max <- length(obtenerTodosCPEs(doc))

  df <- data.frame(cve = character(max),
             cpe = character(max),
             cvss = numeric(max))

  cves <- obtenerCVEs(xmlFile)

  longcves <- length(cves)

  for (i in 1:longcves) {
    print("OBTENIEND CPES")
    cpes <- obtenerCPEbyCVE(xmlFile,cves[[i]])
    print("OBTENIENDO CVSS")
    cvss <- obtenerCVSSbyCVE(xmlFile,cves[[i]])

    for (j in 1:length(cpes)) {
      texto <- sprintf("%s %s %s",cves[[i]],cpes[[j]],cvss[[1]])
      print(texto)
    }
  }

  return(df)
}

#Obtiene todos los CVEs
obtenerCVEs <- function(doc) {
  return(xpathApply(doc,"//vuln:cve-id",xmlValue))
}
#Obtiene todos los CPE's de los CVEs, pero todos concatenados
obtenerCPEs <- function(doc) {
  return(xpathApply(doc,"//vuln:vulnerable-software-list"))
}

#Obtener CPE a partir de un CVE
obtenerCPEbyCVE <- function(doc, cve) {
  #cpes <- xpathApply(doc,"//entry[@id='", cve, "']")

  listNodes <- xmlToList(doc)
  longLista <- length(listNodes)-1
  i <- 1
  encontrado <- FALSE

  while (i<=longLista && !encontrado) {
    if (cve == listNodes[[i]]$`cve-id`) {
      encontrado <- TRUE
      cpes <- listNodes[[i]]$`vulnerable-software-list`
    }
    i<-i+1
  }
  return(cpes)
}

#Obtiene todos los CPE's separados, esto es para poder crear los dataframes.
obtenerTodosCPEs <- function(doc) {
  return (xpathApply(doc,"//vuln:product"))
}

#Obtiene todos los CVSS's
obtenerCVSS <- function(doc) {
  return(xpathApply(doc,"//cvss:score",xmlValue))
}

#Obtener CPE a partir de un CVE
obtenerCVSSbyCVE <- function(doc, cve) {
  #cpes <- xpathApply(doc,"//entry[@id='", cve, "']")

  listNodes <- xmlToList(doc)
  longLista <- length(listNodes)-1
  i <- 1
  encontrado <- FALSE

  while (i<=longLista && !encontrado) {
    if (cve == listNodes[[i]]$`cve-id`) {
      encontrado <- TRUE
      cvss <- listNodes[[i]]$cvss$base_metrics$score
    }
    i<-i+1
  }
  return(cvss)
}


#Obtiene todos los AccesVector
obtenerAccesVector <- function(doc) {
  return(xpathApply(doc,"//cvss:access-vector",xmlValue))
}

montarDF <- function(doc) {
  return (
    data.frame (
      "cves"=c(unlist(obtenerCVEs(doc))),
      "cpes"=c(unlist(obtenerCPEs(doc))),
      "cvss"=c(unlist(obtenerCVSS(doc))))
  )
}

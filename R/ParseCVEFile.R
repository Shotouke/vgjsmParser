#Obtain all CVEs codes
obtenerCVEs <- function(doc) {
  return(xpathApply(doc,"//vuln:cve-id",xmlValue))
}

#Obtain all CPEs by CVEs, all concatenated
obtenerCPEs <- function(doc) {
  return(xpathApply(doc,"//vuln:vulnerable-software-list"))
}

obtencve<- function(doc, cve) {
  path <- paste("//entry[@id='", cve, "']/",sep="")
  cpes <- xpathApply(doc,path)
  return(cpes)
}

#Obtain CPE from CVE
obtenerCPEbyCVE <- function(doc, cve) {
  longLista <- length(doc)-1
  i <- 1
  encontrado <- FALSE

  while (i<=longLista && !encontrado) {
    if (cve == doc[[i]]$`cve-id`) {
      encontrado <- TRUE
      cpes <- doc[[i]]$`vulnerable-software-list`
    }
    i<-i+1
  }

  return(cpes)
}

#Obtain all CPEs separated, this is to allow us create DataFrames
obtenerTodosCPEs <- function(doc) {
  return (xpathApply(doc,"//vuln:product"))
}

#Obtain all CVSSs
obtenerCVSS <- function(doc) {
  return(xpathApply(doc,"//cvss:score",xmlValue))
}

#Obtain CPE fom CVE
obtenerCVSSbyCVE <- function(doc, cve) {
  longLista <- length(doc)-1
  i <- 1
  encontrado <- FALSE

  while (i<=longLista && !encontrado) {
    if (cve == doc[[i]]$`cve-id`) {
      encontrado <- TRUE
      cvss <- doc[[i]]$cvss$base_metrics$score
    }
    i<-i+1
  }

  return(cvss)
}

#Obtain all AccessVector
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

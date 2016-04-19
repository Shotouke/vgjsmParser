lee <- function (fichero) {
  #setwd("/home/jorge/R/_Trabajo Datamining/NVD/")
  library(XML)
  doc <- XML::xmlTreeParse(fichero,useInternal=FALSE)
  return(doc)
}

escribe <- function(result,fichero) {
  nombre<-paste(fichero,".csv")
  write(result,nombre)
}

obtenerVulnYSoft <- function(doc) {
  
  ##aqui devolveremos el resultado
  cvesoft <- c()
  
  rootNode = XML::xmlRoot(doc)
  
  numroot = length(rootNode)
  
  for (i in 1:numroot) {
    #for (i in 1:1) {
    print(i)
    
    lnom <- XML::xpathSApply(rootNode[[i]],"//entry") #Obtengo la etrada "entry"
    cve <- lnom[[2]][[1]] ## obtengo el id de la entrada entry
    print(cve)
    
    ## Obtengo el soft que es vulnerable
    cpes <- XML::xmlChildren(rootNode[[i]])["vulnerable-software-list"][[1]]
    lcpes = xmlSize(cpes)
    #print(lcpes)
    #recorro todo el soft vulnerable
    for (j in 1:lcpes) {
      strcpes <- xmlValue(cpes[[j]][[1]])
      #print(strcpes)
      texto <- sprintf("%s,%s",cve,strcpes)
      #print(texto)
      cvesoft <-c(cvesoft,texto)
    }
  }
  return(cvesoft)
}


procesaFichero <- function(fichero) {
  fich<-lee(fichero)
  result <- obtenerVulnYSoft(fich)
  escribe(result,fichero)
  return(result)
}

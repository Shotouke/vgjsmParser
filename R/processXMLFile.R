readXML <- function (file) {
  library(XML)
  doc <- XML::xmlTreeParse(file,useInternal=TRUE)
  return(doc)
}

writeXML <- function(result,file) {
  name <- paste(file,".csv")
  write(result,name)
}

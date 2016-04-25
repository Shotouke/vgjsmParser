readXMLFile <- function (file) {
  library(XML)
  doc <- XML::xmlTreeParse(file,useInternal=TRUE)
  return(doc)
}

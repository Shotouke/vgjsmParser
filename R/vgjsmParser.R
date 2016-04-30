vgjsmParser <- function() {
  # Load first XML file
  xmlPath <- "../inst/extdata/nvdcve-2.0-2016.xml"
  xmlFile <- readXMLFile(file = xmlPath)

  # Load second XML file
  xmlPath2 <- "../inst/extdata/nvdcve-2.0-2015.xml"
  xmlFile2 <- readXMLFile(file = xmlPath2)

  # Load third XML file
  xmlPath3 <- "../inst/extdata/nvdcve-2.0-2014.xml"
  xmlFile3 <- readXMLFile(file = xmlPath3)

  # Load fourth XML file
  xmlPath4 <- "../inst/extdata/nvdcve-2.0-2013.xml"
  xmlFile4 <- readXMLFile(file = xmlPath4)

  # Initialize DataFrame
  df <- initialize_dataframe(xmlFile, xmlFile2, xmlFile3, xmlFile4)

  # Convert from XML to list of two files
  nodeList <- xmlToList(node = xmlFile)
  nodeList2 <- xmlToList(node = xmlFile2)
  nodeList3 <- xmlToList(node = xmlFile3)
  nodeList4 <- xmlToList(node = xmlFile4)

  # Load OS file
  listSOs<-read.csv("../inst/extdata/SO.csv", header = FALSE)
  listSOs<-levels(listSOs$V1)

  #  Obtain vulnerabilities (CVEs) of  microsoft and android from first XML file
  for (i in 1:length(listSOs)) {
    df <- save_content(xmlFile, nodeList,df,listSOs[[i]])
    df <- save_content(xmlFile2, nodeList2,df,listSOs[[i]])
    df <- save_content(xmlFile3, nodeList3,df,listSOs[[i]])
    df <- save_content(xmlFile4, nodeList4,df,listSOs[[i]])
  }

  # Delete empty rows
  return(deleteEmptyRows(df))
}

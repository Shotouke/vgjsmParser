vgjsmParser <- function() {
  # Load sources
  source('~/vgjsmParser/R/dataFrame.R')
  source('~/vgjsmParser/R/ParseCVEFile.R')
  source('~/vgjsmParser/R/readXMLFile.R')

  # Load first XML file
  xmlPath <- "./inst/extdata/nvdcve-2.0-2016.xml"
  xmlFile <- readXMLFile(file = xmlPath)

  # Load second XML file
  xmlPath2 <- "./inst/extdata/nvdcve-2.0-2015.xml"
  xmlFile2 <- readXMLFile(file = xmlPath2)

  # Initialize DataFrame
  df <- initialize_dataframe(xmlFile, xmlFile2)

  # Convert from XML to list of two files
  nodeList <- xmlToList(node = xmlFile)
  nodeList2 <- xmlToList(node = xmlFile2)

  # Obtain vulneravilities (CVEs) of  microsoft and android from first XML file
  df <- save_content(xmlFile, nodeList, df, "microsoft")
  df <- save_content(xmlFile, nodeList, df, "android")

  # Obtain vulneravilities (CVEs) of  microsoft and android from second XML file
  df <- save_content(xmlFile2, nodeList2, df, "microsoft")
  df <- save_content(xmlFile2, nodeList2, df, "android")

  # Delete empty rows
  return(deleteEmptyRows(df))
}

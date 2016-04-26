#Carga del primer fichero
xmlPath   <- "./inst/extdata/nvdcve-2.0-2016.xml"
xmlFile <- readXMLFile(xmlPath)
#carga del segundo fichero
xmlPath2   <- "./inst/extdata/nvdcve-2.0-2015.xml"
xmlFile2 <- readXMLFile(xmlPath2)
df <-crear_dataframe(xmlFile, xmlFile2)
#Conversión de xml a Lista de los 2 ficheros
listaNodo <- xmlToList(xmlFile)
listaNodo2<- xmlToList(xmlFile2)
#Obtencion de vulnerabilidades (CVEs) de microsoft y android del Primer fichero
df <- crear_contenido(xmlFile, listaNodo,df)
df <- crear_contenido(xmlFile, listaNodo,df,"android")
#Obtencion de vulnerabilidades (CVEs) de microsoft y android del Segundo fichero
df <- crear_contenido(xmlFile2, listaNodo2,df)
df <- crear_contenido(xmlFile2, listaNodo2,df,"android")

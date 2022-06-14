output <- read.csv(file = '/home/sergio/GolandProjects/bulkanalyzer/testdata/eth_contracts_2020_2022_10000_samples.csv_out.csv', stringsAsFactors = TRUE)
summary(output)

plot(x = seq(1, length(output$coverage)), y = output$coverage,
     xlab = "sample",
     ylab = "coverage %",
     main = "Coverage"
)
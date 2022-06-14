## Input source files

Input source files as `csv` have been downloaded using following script. Modify SQL query condition as desired to obtain a different dataset.

```py
import os
import numpy as np
import pandas as pd
from google.cloud import bigquery

#os.remove("/kaggle/working/eth_contracts_2017.csv")
#os.remove("/kaggle/working/eth_contracts_2018.csv")
client = bigquery.Client()
print("executing Big Query against Google and Kaggle systems...")

# download all contract code from ETH
query = """
SELECT address, bytecode, function_sighashes, is_erc20, is_erc721, block_timestamp, block_number from `bigquery-public-data.crypto_ethereum.contracts`
WHERE DATE(block_timestamp) BETWEEN "2019-01-01" and "2019-12-31" and bytecode != "0x" ORDER BY rand() LIMIT 10000;
"""

print("querying...")
df = client.query(query).to_dataframe()

fname = 'eth_contracts_2019_10000.csv'
print("converting to CSV")
df.to_csv(fname)

print("done")
```

## References

* https://www.kaggle.com/
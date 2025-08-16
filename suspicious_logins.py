import sqlite3, pandas as pd

#connect to database
con=sqlite3.connect("logins.db")

#Querry for users with more than 2 unique ips in the same day
q="""
SELECT username, date(timestamp) AS day,
COUNT(DISTINCT ip_address) AS ip_count
FROM logins
GROUP BY username, day
HAVING ip_count > 2
"""

#load data into dataframe
df=pd.read_sql_query(q, con)
df.to_csv("hits.csv", index="False")

#display number of hits
print(f"Wrote {len(df)} rows")





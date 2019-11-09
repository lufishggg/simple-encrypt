// examples
package main

import (
	"fmt"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	se "simple-encrypt"
	"time"
	"xorm.io/builder"
)

type User struct {
	Id int64 `db:"id"`
	Name se.EncryptString `db:"name"`
	Email se.EncryptString `db:"email"`
	Gender int `db:"gender"`
	EncryptedGender se.EncryptInt `db:"encrypted_gender"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

/*
	If we already have a table 'users' like this (use pg as example), and there have been some records:

	CREATE TABLE users (
	  id BIGSERIAL PRIMARY KEY,
	  name VARCHAR,
	  email VARCHAR UNIQUE,
	  gender smallint DEFAULT 0,
	  created_at TIMESTAMP NOT NULL,
	  updated_at TIMESTAMP NOT NULL
	)

	id |   name  |      email       |        gender      |          created_at           |             updated_at
	------------------------------------------------------------------------------------------------------------------------
	1  |  john	 | john@gmail.com	|          1	     |   2019-11-05 21:09:20.30628	 |      2019-11-05 21:09:20.30628
	2  |  mike	 | mike@gmail.com	|          2	     |   2019-11-05 21:09:20.30628	 |      2019-11-05 21:09:20.30628
	3  |  Tom	 |	                |          1	     |   2019-11-05 21:09:20.30628	 |      2019-11-05 21:09:20.30628
	4  |  ""	 |	                |          0	     |   2019-11-05 21:09:20.30628	 |      2019-11-05 21:09:20.30628

	Now we want to encrypt the remain records (even gender!) and future records.
	Run main(), and we can get the output:
		original data in database:
		id: 1, name: john, email: john@gmail.com, gender: 1, encrypted_gender: 0

		encrypted data in database, it is absolutely the same with the original data!:
		id: 1, name: john, email: john@gmail.com, gender: 0, encrypted_gender: 1

		original data in database:
		id: 2, name: mike, email: mike@gmail.com, gender: 2, encrypted_gender: 0

		encrypted data in database, it is absolutely the same with the original data!:
		id: 2, name: mike, email: mike@gmail.com, gender: 0, encrypted_gender: 2

		original data in database:
		id: 3, name: tom, email: , gender: 1, encrypted_gender: 0

		encrypted data in database, it is absolutely the same with the original data!:
		id: 3, name: tom, email: , gender: 0, encrypted_gender: 1

		original data in database:
		id: 4, name: "", email: , gender: 0, encrypted_gender: 0

		encrypted data in database, it is absolutely the same with the original data!:
		id: 4, name: "", email: , gender: 0, encrypted_gender: 0
*/
func main()  {
	db, _ := sqlx.Open("postgres", "postgres://docker:docker@127.0.0.1:35432/gis?sslmode=disable")
	defer db.Close()
	// First we have to create a new column for encrypting gender, let's call it encrypted_gender
	_, _ = db.Exec("ALTER TABLE users ADD encrypted_gender VARCHAR DEFAULT '0';")
	// We have to init the key. That is all what we should do!
	_ = se.InitDefaultKey("0123456789abcdef0123456789abcdef")
	user := User{
		Name:            se.NewEncryptString(nil),
		Email:           se.NewEncryptString(nil),
		EncryptedGender: se.NewEncryptInt(nil),
	}
	for i := 1; i < 5; i++ {
		// Get original records
		query, args, _ := builder.Postgres().Select("*").From("users").Where(builder.Eq{"id": i}).ToSQL()
		// Attention that even if there is some error (it is unavoidable because the original records are not cipher texts), we still scan the values!
		// This is for encrypting the remain data that we can easily encrypt the data just by simply scan and insert
		_ = db.Get(&user, query, args...)
		fmt.Println("original data in database:")
		fmt.Printf("id: %d, name: %s, email: %s, gender: %d, encrypted_gender: %d\n", user.Id, user.Name.String(), user.Email.String(), user.Gender, user.EncryptedGender.Int())
		// Simply update the data in the table again
		query, args, _ = builder.Postgres().Update(builder.Eq{
			"name": user.Name,
			"email": user.Email,
			"gender": 0,// Set gender to be 0
			"encrypted_gender": se.NewEncryptInt(&user.Gender),// Set encrypted_gender to be original gender
		}).From("users").Where(builder.Eq{"id": i}).ToSQL()
		_, _ = db.Exec(query, args...)
		/*
			Here, we have encrypted the data, in database looks like just as:
			id     |                          name                     |                  email                       | gender |         created_at            |         updated_at          | 		       encrypted_gender
		---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
			1      |      p7XdzCkfo4V4HeX/ejSC48t315BZaJkV182aikZK/Qw= | BfjZss+4SgoaxPWKR8kKmzfMB9VVx3qy9gZ4R1ep1hA= |    0   |    2019-11-05 21:09:20.30628  |  2019-11-05 21:09:20.30628  |   HRAgIgXmlSqZ5bs483ekL4fahD7dhexlS/Fs9Ezr/Ec=
			2	   |      wtifiMEwTRXXw5pAbfVlkzSpBzJXTzg/Xq9kVsy3CaE= | WaxG+BZ/UKHwJ7+6qAcKUaqccPTRUdg15A9oTR0vVw4= |	   0   |    2019-11-05 21:09:20.30628  |  2019-11-05 21:09:20.30628  |   i6T6BuzdcWZKHBGoeJX1KU667FuK4NR6IHhsepArWx0=
			3	   |      lPJLPkbNREZEBkmAL62OkgJk806xIZn5IVyhu2/patk= |	                                          |    0   |    2019-11-05 21:09:20.30628  |  2019-11-05 21:09:20.30628  |   jzAf9hN14eLoM5zYyeHJ9iTNi/4siEMB6IQFmXQ4oRg=
			4	   |      3foz2J7IG7BNn29IOUUsNGwRDPX2q9R6ezy2YlNFoXE= |	                                       	  |	   0   |    2019-11-05 21:09:20.30628  |  2019-11-05 21:09:20.30628  |  A19kMvFUJbSAQNYI4HykbTvQe/EhEyuozEOndZwJgZw=

			Next, get the record and check its value
		 */

		// Get encrypted data
		query, args, _ = builder.Postgres().Select("*").From("users").Where(builder.Eq{"id": i}).ToSQL()
		_ = db.Get(&user, query, args...)
		fmt.Println("encrypted data in database, it is absolutely the same with the original data!:")
		fmt.Printf("id: %d, name: %s, email: %s, gender: %d, encrypted_gender: %d\n", user.Id, user.Name.String(), user.Email.String(), user.Gender, user.EncryptedGender.Int())
	}
}

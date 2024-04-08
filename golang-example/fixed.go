package main

import (
    "database/sql"
    "fmt"
    "log"
    "net/http"
    "github.com/go-sql-driver/mysql"
)

var db *sql.DB
var err error

func initDB() {
    db, err = sql.Open("mysql", "user:password@/dbname")
    if err != nil {
        log.Fatal(err)
    }

    err = db.Ping()
    if err != nil {
        log.Fatal(err)
    }
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
        http.Error(w, "Method is not supported.", http.StatusNotFound)
        return
    }

    searchQuery := r.URL.Query().Get("query")
    if searchQuery == "" {
        http.Error(w, "Query parameter is missing", http.StatusBadRequest)
        return
    }

    rows, err := db.Query("SELECT * FROM products WHERE name LIKE ?", searchQuery)
    if err != nil {
        http.Error(w, "Query failed", http.StatusInternalServerError)
        log.Println(err)
        return
    }
    defer rows.Close()

    var products []string
    for rows.Next() {
        var name string
        err := rows.Scan(&name)
        if err != nil {
            log.Fatal(err)
        }
        products = append(products, name)
    }

    fmt.Fprintf(w, "Found products: %v\n", products)
}

func main() {
    initDB()
    defer db.Close()

    http.HandleFunc("/search", searchHandler)
    fmt.Println("Server is running")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
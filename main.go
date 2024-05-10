package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type User struct {
	Username string
	Password string
	Type     string
}

var users = []User{
	{Username: "admin", Password: "admin123", Type: "admin"},
	{Username: "user", Password: "user123", Type: "regular"},
}

func main() {
	router := gin.Default()

	router.POST("/login", login)
	router.GET("/home", authorizeJWT(), home)
	router.POST("/addBook", authorizeJWT(), addBook)
	router.POST("/deleteBook", authorizeJWT(), deleteBook)

	router.Run(":8080")
}

func login(c *gin.Context) {
	var loginDetails User
	if err := c.ShouldBindJSON(&loginDetails); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	for _, user := range users {
		if user.Username == loginDetails.Username && user.Password == loginDetails.Password {
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"username": loginDetails.Username,
				"type":     user.Type,
				"exp":      time.Now().Add(time.Hour * 2).Unix(),
			})

			tokenString, err := token.SignedString([]byte("secret"))
			if err != nil {
				c.JSON(500, gin.H{"error": "Could not generate token"})
				return
			}

			c.JSON(200, gin.H{"token": tokenString})
			return
		}
	}

	c.JSON(401, gin.H{"error": "Invalid credentials"})
}

func authorizeJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		const Bearer_schema = "Bearer "
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "Authorization header is required"})
			return
		}

		tokenString := authHeader[len(Bearer_schema):]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return []byte("secret"), nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("username", claims["username"])
			c.Set("userType", claims["type"])
		} else {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token", "details": err})
			return
		}
	}
}

func home(c *gin.Context) {
	userType := c.MustGet("userType").(string)
	books := readBooks("regularUser.csv")

	if userType == "admin" {
		adminBooks := readBooks("adminUser.csv")
		books = append(books, adminBooks...)
	}

	c.JSON(200, gin.H{"books": books})
}

func addBook(c *gin.Context) {
	userType := c.MustGet("userType").(string)
	if userType != "admin" {
		c.JSON(403, gin.H{"error": "Unauthorized access"})
		return
	}

	var bookDetails struct {
		BookName       string `json:"bookName"`
		Author         string `json:"author"`
		PublicationYear int    `json:"publicationYear"`
	}

	if err := c.ShouldBindJSON(&bookDetails); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	if bookDetails.BookName == "" || bookDetails.Author == "" || !isValidYear(bookDetails.PublicationYear) {
		c.JSON(400, gin.H{"error": "Invalid book details"})
		return
	}

	file, err := os.OpenFile("regularUser.csv", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to open file"})
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{bookDetails.BookName, bookDetails.Author, strconv.Itoa(bookDetails.PublicationYear)}); err != nil {
		c.JSON(500, gin.H{"error": "Failed to write to file"})
		return
	}

	c.JSON(200, gin.H{"message": "Book added successfully"})
}

func deleteBook(c *gin.Context) {
	userType := c.MustGet("userType").(string)
	if userType != "admin" {
		c.JSON(403, gin.H{"error": "Unauthorized access"})
		return
	}

	bookName := c.Query("bookName")
	if bookName == "" {
		c.JSON(400, gin.H{"error": "Book name is required"})
		return
	}

	books := readBooks("regularUser.csv")
	filteredBooks := []string{}

	for _, b := range books {
		if strings.ToLower(b) != strings.ToLower(bookName) {
			filteredBooks = append(filteredBooks, b)
		}
	}

	file, err := os.Create("regularUser.csv")
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to open file"})
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, book := range filteredBooks {
		if err := writer.Write([]string{book}); err != nil {
			c.JSON(500, gin.H{"error": "Failed to write to file"})
			return
		}
	}

	c.JSON(200, gin.H{"message": "Book deleted successfully"})
}

func readBooks(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		return []string{}
	}
	defer file.Close()

	reader := csv.NewReader(file)
	var books []string
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		books = append(books, record[0])
	}
	return books
}

func isValidYear(year int) bool {
	currentYear := time.Now().Year()
	return year >= 1000 && year <= currentYear
}

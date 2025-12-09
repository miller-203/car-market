package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// --- Models ---
type Car struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Brand       string    `json:"brand"`
	Model       string    `json:"model"`
	Year        int       `json:"year"`
	Mileage     int       `json:"mileage"`
	Price       int       `json:"price"`
	Description string    `json:"description"`
	ImageURL    string    `json:"image_url"`
	CreatedAt   time.Time `json:"created_at"`
}

type Admin struct {
	ID           uint   `json:"id" gorm:"primaryKey"`
	Username     string `json:"username" gorm:"unique"`
	PasswordHash string `json:"-"`
}

// --- Global Variables ---
var (
	DB        *gorm.DB
	jwtSecret []byte
)

// --- Database Connection ---
func connectDB() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL not set")
	}
	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	// Auto Migrate
	DB.AutoMigrate(&Car{}, &Admin{})
	fmt.Println("Database Connected & Migrated")
}

// --- Utils ---
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// --- Middleware ---
func authRequired(c *fiber.Ctx) error {
	tokenString := c.Get("Authorization")
	if len(tokenString) < 7 {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}
	tokenString = tokenString[7:] // Remove "Bearer "

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid Token"})
	}
	return c.Next()
}

// --- Handlers ---

// Public: Get All Cars
func getCars(c *fiber.Ctx) error {
	var cars []Car
	DB.Order("created_at desc").Find(&cars)
	return c.JSON(cars)
}

// Public: Get Single Car
func getCar(c *fiber.Ctx) error {
	id := c.Params("id")
	var car Car
	if result := DB.First(&car, id); result.Error != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Car not found"})
	}
	return c.JSON(car)
}

// Public: Login
func login(c *fiber.Ctx) error {
	type LoginInput struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	var input LoginInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Bad Request"})
	}

	var admin Admin
	if result := DB.Where("username = ?", input.Username).First(&admin); result.Error != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	if !checkPassword(input.Password, admin.PasswordHash) {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// Create JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"admin_id": admin.ID,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

	t, err := token.SignedString(jwtSecret)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Could not login"})
	}

	return c.JSON(fiber.Map{"token": t})
}

// Admin: Add Car
func createCar(c *fiber.Ctx) error {
	// Parse multipart form
	_, err := c.MultipartForm()
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Parse error"})
	}

	// Handle Image Upload
	file, err := c.FormFile("image")
	imagePath := ""
	if err == nil {
		// Save file to ./uploads
		filename := fmt.Sprintf("%d_%s", time.Now().Unix(), file.Filename)
		imagePath = fmt.Sprintf("/uploads/%s", filename)
		c.SaveFile(file, "."+imagePath)
	}

	// Parse other fields manually or via struct if sending JSON.
	// Since we use FormData for file upload, we extract strings manually:
	year, _ := strconv.Atoi(c.FormValue("year"))
	mileage, _ := strconv.Atoi(c.FormValue("mileage"))
	price, _ := strconv.Atoi(c.FormValue("price"))

	car := Car{
		Brand:       c.FormValue("brand"),
		Model:       c.FormValue("model"),
		Year:        year,
		Mileage:     mileage,
		Price:       price,
		Description: c.FormValue("description"),
		ImageURL:    imagePath,
	}

	DB.Create(&car)
	return c.Status(201).JSON(car)
}

// Admin: Delete Car
func deleteCar(c *fiber.Ctx) error {
	id := c.Params("id")
	var car Car
	if result := DB.First(&car, id); result.Error != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Not found"})
	}

	// Optional: Delete local image file here using os.Remove(car.ImageURL)

	DB.Delete(&car)
	return c.SendStatus(204)
}

// Setup Admin (Run once manually via code or SQL to create user)
func setupAdmin(c *fiber.Ctx) error {
	hash, _ := hashPassword("admin123")
	admin := Admin{Username: "admin", PasswordHash: hash}
	DB.Create(&admin)
	return c.JSON(admin)
}

func main() {
	// Load .env
	if err := godotenv.Load("../.env"); err != nil {
		log.Println("No .env file found, relying on system envs")
	}

	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	connectDB()

	app := fiber.New()

	app.Use(cors.New())

	// --- 2. SERVE FRONTEND FILES (ADD THIS) ---
	// This tells Go to serve index.html, style.css, etc. from the frontend folder
	// when you visit http://localhost:3000/
	app.Static("/", "./frontend")
	
	// Serve uploaded images
	app.Static("/uploads", "./uploads")

	// Routes
	app.Get("/cars", getCars)
	app.Get("/cars/:id", getCar)
	app.Post("/admin/login", login)
	
	// app.Post("/create-seed-admin", setupAdmin) // Keep commented out if you are done

	// Protected Routes
	admin := app.Group("/admin", authRequired)
	admin.Post("/cars", createCar)
	admin.Delete("/cars/:id", deleteCar)

	// --- 3. CUSTOM 404 HANDLER (ADD THIS AT THE END) ---
	// If a user tries a link that doesn't exist, show a nice JSON error
	app.Use(func(c *fiber.Ctx) error {
		return c.Status(404).JSON(fiber.Map{
			"error": "404 Not Found",
			"message": "The page or API endpoint you are looking for does not exist.",
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Fatal(app.Listen(":" + port))
}
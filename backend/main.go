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

type CarImage struct {
	ID       uint   `json:"id" gorm:"primaryKey"`
	CarID    uint   `json:"-"`
	ImageURL string `json:"image_url"`
}

type Car struct {
	ID          uint       `json:"id" gorm:"primaryKey"`
	Brand       string     `json:"brand"`
	Model       string     `json:"model"`
	Year        int        `json:"year"`
	Mileage     int        `json:"mileage"`
	Price       int        `json:"price"`
	Description string     `json:"description"`
	ImageURL    string     `json:"image_url"` // Main thumbnail
	Images      []CarImage `json:"images" gorm:"foreignKey:CarID"` // Gallery
	CreatedAt   time.Time  `json:"created_at"`
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
	DB.AutoMigrate(&Car{}, &Admin{}, &CarImage{})
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
    // Add .Preload("Images") to fetch the gallery
	if result := DB.Preload("Images").First(&car, id); result.Error != nil {
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
    // 1. Parse Multipart Form
    form, err := c.MultipartForm()
    if err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Parse error"})
    }

    // 2. Prepare basic car data
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
    }

    // 3. Handle Multiple Images
    files := form.File["images"] // Frontend must use name="images"
    var gallery []CarImage

    for i, file := range files {
        // Create unique filename
        filename := fmt.Sprintf("%d_%d_%s", time.Now().Unix(), i, file.Filename)
        path := fmt.Sprintf("/uploads/%s", filename)

        // Save to disk
        if err := c.SaveFile(file, "."+path); err != nil {
            fmt.Println("Error saving file:", err)
            continue
        }

        // First image becomes the "Main Thumbnail"
        if i == 0 {
            car.ImageURL = path
        }

        // Add to gallery list
        gallery = append(gallery, CarImage{ImageURL: path})
    }

    car.Images = gallery

    // 4. Save to DB
    if result := DB.Create(&car); result.Error != nil {
        return c.Status(500).JSON(fiber.Map{"error": "Database error"})
    }

    return c.Status(201).JSON(car)
}

// Admin: Delete Car
// Admin: Delete Car
func deleteCar(c *fiber.Ctx) error {
    id := c.Params("id")
    var car Car

    // 1. Find the car AND load its images so we know what to delete
    if result := DB.Preload("Images").First(&car, id); result.Error != nil {
        return c.Status(404).JSON(fiber.Map{"error": "Not found"})
    }

    // 2. Delete the actual files from the "uploads" folder (Clean up disk)
    if car.ImageURL != "" {
        err := os.Remove("." + car.ImageURL) // Remove main image
        if err != nil {
            fmt.Println("Failed to delete main image:", err)
        }
    }

    for _, img := range car.Images {
        err := os.Remove("." + img.ImageURL) // Remove gallery images
        if err != nil {
            fmt.Println("Failed to delete gallery image:", err)
        }
    }

    // 3. Delete the Gallery Records from Database first (Fixes the Foreign Key Error)
    if err := DB.Where("car_id = ?", car.ID).Delete(&CarImage{}).Error; err != nil {
         return c.Status(500).JSON(fiber.Map{"error": "Could not delete car images"})
    }

    // 4. Finally, Delete the Car
    if err := DB.Delete(&car).Error; err != nil {
        return c.Status(500).JSON(fiber.Map{"error": "Could not delete car"})
    }

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
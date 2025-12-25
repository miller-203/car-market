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
	ID           uint       `json:"id" gorm:"primaryKey"`
	Brand        string     `json:"brand"`
	Model        string     `json:"model"`
	Year         int        `json:"year"`
	Mileage      int        `json:"mileage"`
	Price        int        `json:"price"`
	Description  string     `json:"description"`
	ImageURL     string     `json:"image_url"`
	Images       []CarImage `json:"images" gorm:"foreignKey:CarID"`
	
	// New Fields
	Transmission string     `json:"transmission"`
	FuelType     string     `json:"fuel_type"`
	Doors        int        `json:"doors"`
	Origin       string     `json:"origin"`
	FiscalPower  int        `json:"fiscal_power"`
	Condition    string     `json:"condition"`
	
	CreatedAt    time.Time  `json:"created_at"`
}

type Admin struct {
	ID           uint   `json:"id" gorm:"primaryKey"`
	Username     string `json:"username" gorm:"unique"`
	PasswordHash string `json:"-"`
}

var (
	DB        *gorm.DB
	jwtSecret []byte
)

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
	DB.AutoMigrate(&Car{}, &Admin{}, &CarImage{})
	fmt.Println("Database Connected & Migrated")
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func authRequired(c *fiber.Ctx) error {
	tokenString := c.Get("Authorization")
	if len(tokenString) < 7 {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}
	tokenString = tokenString[7:] 

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid Token"})
	}
	return c.Next()
}

func getCars(c *fiber.Ctx) error {
	var cars []Car
	if result := DB.Preload("Images").Order("created_at desc").Find(&cars); result.Error != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}
	return c.JSON(cars)
}

func getCar(c *fiber.Ctx) error {
	id := c.Params("id")
	var car Car
	if result := DB.Preload("Images").First(&car, id); result.Error != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Car not found"})
	}
	return c.JSON(car)
}

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
    form, err := c.MultipartForm()
    if err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Parse error"})
    }

    year, _ := strconv.Atoi(c.FormValue("year"))
    mileage, _ := strconv.Atoi(c.FormValue("mileage"))
    price, _ := strconv.Atoi(c.FormValue("price"))
    doors, _ := strconv.Atoi(c.FormValue("doors"))
    fiscalPower, _ := strconv.Atoi(c.FormValue("fiscal_power"))

    car := Car{
        Brand:        c.FormValue("brand"),
        Model:        c.FormValue("model"),
        Year:         year,
        Mileage:      mileage,
        Price:        price,
        Description:  c.FormValue("description"),
        Transmission: c.FormValue("transmission"),
        FuelType:     c.FormValue("fuel_type"),
        Doors:        doors,
        Origin:       c.FormValue("origin"),
        FiscalPower:  fiscalPower,
        Condition:    c.FormValue("condition"),
    }

    files := form.File["images"]
    var gallery []CarImage

    // --- FIX START: Create 'uploads' folder if it doesn't exist ---
    if _, err := os.Stat("./uploads"); os.IsNotExist(err) {
        os.MkdirAll("./uploads", 0755)
    }
    // --- FIX END ---

    for i, file := range files {
        filename := fmt.Sprintf("%d_%d_%s", time.Now().Unix(), i, file.Filename)
        path := fmt.Sprintf("/uploads/%s", filename)

        if err := c.SaveFile(file, "."+path); err != nil {
            fmt.Println("Error saving file:", err)
            continue
        }

        if i == 0 {
            car.ImageURL = path
        }
        gallery = append(gallery, CarImage{ImageURL: path})
    }

    car.Images = gallery

    if result := DB.Create(&car); result.Error != nil {
        return c.Status(500).JSON(fiber.Map{"error": "Database error"})
    }

    return c.Status(201).JSON(car)
}

func deleteCar(c *fiber.Ctx) error {
	id := c.Params("id")
	var car Car
	if result := DB.Preload("Images").First(&car, id); result.Error != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Not found"})
	}
    
    // Clean up files
    if car.ImageURL != "" { os.Remove("." + car.ImageURL) }
    for _, img := range car.Images { os.Remove("." + img.ImageURL) }
    DB.Where("car_id = ?", car.ID).Delete(&CarImage{})

	DB.Delete(&car)
	return c.SendStatus(204)
}

func main() {
	if err := godotenv.Load("../.env"); err != nil {
		log.Println("No .env file found")
	}

	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	connectDB()

	app := fiber.New()
	app.Use(cors.New())
	app.Static("/", "./frontend")
	app.Static("/uploads", "./uploads")

	app.Get("/cars", getCars)
	app.Get("/cars/:id", getCar)
	app.Post("/admin/login", login)

	admin := app.Group("/admin", authRequired)
	admin.Post("/cars", createCar)
	admin.Delete("/cars/:id", deleteCar)

	app.Use(func(c *fiber.Ctx) error {
		return c.Status(404).JSON(fiber.Map{"error": "404 Not Found"})
	})

	port := os.Getenv("PORT")
	if port == "" { port = "3000" }
	log.Fatal(app.Listen(":" + port))
}
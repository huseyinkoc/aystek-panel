package services

import (
	"admin-panel/models"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"plugin"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var pluginCollection *mongo.Collection

func InitPluginService(client *mongo.Client) {
	pluginCollection = client.Database("admin_panel").Collection("plugins")
}

// CreatePlugin adds a new plugin
func CreatePlugin(plugin *models.Plugin) error {
	plugin.ID = primitive.NewObjectID()
	plugin.CreatedAt = primitive.NewDateTimeFromTime(time.Now())
	plugin.UpdatedAt = primitive.NewDateTimeFromTime(time.Now())

	_, err := pluginCollection.InsertOne(context.Background(), plugin)
	return err
}

// GetAllPlugins retrieves all plugins
func GetAllPlugins() ([]models.Plugin, error) {
	var plugins []models.Plugin

	cursor, err := pluginCollection.Find(context.Background(), bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var plugin models.Plugin
		if err := cursor.Decode(&plugin); err != nil {
			return nil, err
		}
		plugins = append(plugins, plugin)
	}

	return plugins, nil
}

// UpdatePlugin updates an existing plugin
func UpdatePlugin(id primitive.ObjectID, update bson.M) error {
	update["updated_at"] = primitive.NewDateTimeFromTime(time.Now())
	_, err := pluginCollection.UpdateOne(context.Background(), bson.M{"_id": id}, bson.M{"$set": update})
	return err
}

// DeletePlugin deletes a plugin by ID
func DeletePlugin(id primitive.ObjectID) error {
	_, err := pluginCollection.DeleteOne(context.Background(), bson.M{"_id": id})
	return err
}

func ListUploadedPlugins() ([]string, error) {
	files, err := ioutil.ReadDir("./plugins/")
	if err != nil {
		return nil, err
	}

	var plugins []string
	for _, file := range files {
		plugins = append(plugins, file.Name())
	}

	return plugins, nil
}

func LoadPlugin(pluginPath string) error {
	p, err := plugin.Open(pluginPath)
	if err != nil {
		return err
	}

	// Örneğin bir `Initialize` fonksiyonunu çalıştırmak
	initFunc, err := p.Lookup("Initialize")
	if err != nil {
		return err
	}

	initFunc.(func())() // `Initialize` fonksiyonunu çağır
	return nil
}

func VerifyPluginIntegrity(filePath string, expectedHash string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false, err
	}

	actualHash := fmt.Sprintf("%x", hash.Sum(nil))
	return actualHash == expectedHash, nil
}

func EnablePlugin(pluginID primitive.ObjectID) error {
	_, err := pluginCollection.UpdateOne(
		context.Background(),
		bson.M{"_id": pluginID},
		bson.M{"$set": bson.M{"enabled": true, "updated_at": primitive.NewDateTimeFromTime(time.Now())}},
	)
	return err
}

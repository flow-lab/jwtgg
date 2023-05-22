# jwtgg

This is a test project for generating a JWT token for testing the integration with the [maskinporten](https://samarbeid.digdir.no/maskinporten/maskinporten/25).



### Generate a key pair for testing

    ```shell
    # generate a private key
    openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
    
    # generate a public key
    openssl rsa -pubout -in private_key.pem -out public_key.pem
    ```

### Configure the integration

    ```shell
    # create a new integration in the samarbeidsportalen, follow documentation like in https://autosys-kjoretoy-api.atlas.vegvesen.no/api-ui/index-maskinporten-konsument.html
    # copy the client_id and the client_secret to the .env file
    # copy the public key to the integration in the samarbeidsportalen
    # update the .env file with the correct values
    cp example.env .env
    ```

### Run the application
    
    ```shell
    # install dependencies
    go mod download

    # run the application
    go run main.go
    ```
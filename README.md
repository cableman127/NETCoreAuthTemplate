# ASP.NET Core & EntityFramework Core JWT Authentication template

This template is a simple startup project to start with using ASP.NET Core and EntityFramework Core.

It contains JWT Authentication tokens, Swagger, In-Memory DB and SendGrid email capabilities

Please go to Sendgrid and make an account and get an Email API Key:

https://sendgrid.com/docs/for-developers/sending-email/v3-csharp-code-example/


## Prerequirements

* Visual Studio 2019
* .NET Core SDK 3.1

## How To Run

* Open solution in Visual Studio 2019
* Make sure it has downloaded all the Nuget Packages
* Set Host System SENDGRID_API_KEY environment variable.
    * Within the 'launchSettings.json' file, you can add it so when you run the project via Docker in VS2019, 
    you can add your API_KEY value in there.
* Run the application 'NETCoreAuthAPI.
* It will run on https://localhost:4001 and open up the EDGE browser.
* This is able to be run on Docker as well. (Linux Docker Container)


## Misc.

* There is one endpoint within the AccountController to test the JWT Authentication token: 'TestAuthTokenHere'
* This project requires all User accounts to have their email verified.
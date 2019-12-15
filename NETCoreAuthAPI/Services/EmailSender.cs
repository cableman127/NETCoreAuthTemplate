using Microsoft.Extensions.Options;
using NETCoreAuthAPI.Helpers;
using SendGrid;
using SendGrid.Helpers.Mail;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;


namespace NETCoreAuthAPI.Services
{
    public class EmailSender
    {
        public EmailSender(IOptions<AppSettings> appSettingsAccessor)
        {
            AppSettingsAccessor = appSettingsAccessor.Value;
        }

        public AppSettings AppSettingsAccessor { get; } //set only via Secret Manager

        public Task SendEmailAsync(string email, string subject, string message)
        {
            return Execute(AppSettingsAccessor.SendGridApiKeyEnvironmentVariableName, subject, message, email);
        }

        public Task Execute(string apiKey, string subject, string message, string email)
        {
            var client = new SendGridClient(Environment.GetEnvironmentVariable(apiKey));
            var msg = new SendGridMessage()
            {
                From = new EmailAddress(AppSettingsAccessor.EmailRecipient, "NetCoreAuth"),
                Subject = subject,
                PlainTextContent = message,
                HtmlContent = message
            };
            msg.AddTo(new EmailAddress(email));

            // Disable click tracking.
            // See https://sendgrid.com/docs/User_Guide/Settings/tracking.html
            msg.SetClickTracking(false, false);

            return client.SendEmailAsync(msg);
        }
    }
}

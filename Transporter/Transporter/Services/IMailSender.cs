using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Transporter.Services
{
    public interface IMailSender
    {
        Task SendEmailAsync(string subject, string body, string toEmailAddress);

    }
}

using AutoMapper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Transporter.Models;
using Transporter.ViewModel;

namespace Transporter.Repository
{
    public class AutoMapperProfile: Profile
    {
        public AutoMapperProfile()
        {
            CreateMap<ShippingInfo, CreateOrderVM>().ReverseMap();
        }
    }
}

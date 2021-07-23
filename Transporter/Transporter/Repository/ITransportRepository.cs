using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Transporter.Models;
using Transporter.ViewModel;

namespace Transporter.Repository
{
    public interface ITransportRepository
    {
        void RegisterOrder(ShippingInfo model);

        Task<ShippingInfo> GetOrder(int id);

        Task<ShippingInfo> GetOrder(string trackingNumber);

        Task<bool> CheckIfTrackingNoExist(string trackingNumber);

        void UpdateOrder(ShippingInfo model);

        void DeleteOrder(int id);

        Task<bool> SaveAll();

        Task<IEnumerable<ShippingInfo>> GetAllShipmemnts();
    }
}

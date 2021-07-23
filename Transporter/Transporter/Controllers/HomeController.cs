using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Transporter.Models;
using Transporter.Repository;
using Transporter.ViewModel;

namespace Transporter.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly ITransportRepository _repo;
        private readonly IMapper _mapper;

        public HomeController(ILogger<HomeController> logger, ITransportRepository repo, IMapper mapper)
        {
            _logger = logger;
            _repo = repo;
            _mapper = mapper;
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> register(CreateOrderVM model)
        {

            if (ModelState.IsValid)
            {
                model.TrackingNumber = GenerateTrackingNumber();
                if (await _repo.CheckIfTrackingNoExist(model.TrackingNumber))
                {
                    ModelState.AddModelError("tracking", "The tracking number already exists");
                    return View(model);
                }
                var shipmentMapped = _mapper.Map<ShippingInfo>(model);
                _repo.RegisterOrder(shipmentMapped);

                if (await _repo.SaveAll())
                    return RedirectToAction(nameof(Shipments));


            }
            return View(model);

        }
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult services()
        {
            return View();
        }
        public IActionResult gallery()
        {
            return View();
        }

        public IActionResult contact()
        {
            return View();
        }

        [HttpGet]
        public IActionResult track()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> track(string model)
        {
            if (model != null)
            {
                var shipment = await _repo.GetOrder(model);
                if (shipment == null)
                    return NotFound();
                var shipmentToReturn = _mapper.Map<CreateOrderVM>(shipment);
                return RedirectToAction(nameof(viewInfo), shipment.TransactionId);
            }
            return View(model);
        }

        public async Task<IActionResult> viewInfo(int id)
        {
            var shipment = await _repo.GetOrder(id);
            if (shipment == null)
                return NotFound();
            var shipmentToReturn = _mapper.Map<CreateOrderVM>(shipment);

            return View(shipmentToReturn);
        }

        public async Task<IActionResult> Shipments()
        {
            var shipments = await _repo.GetAllShipmemnts();

            var shipmentsToReturn = _mapper.Map<IEnumerable<CreateOrderVM>>(shipments);

            return View(shipmentsToReturn);
        }

        public IActionResult admin()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public string GenerateTrackingNumber()
        {
            string[] letters = { "A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z",
                                 "0","1", "2", "3", "4", "5", "6", "7", "8","9"};

            var random = new Random();
            string result = "";
            for (int i = 0; i < 16; i++)
            {
                var j = random.Next(0, 35);
                result += letters[j];
            }
            return result;
        }
    }
}

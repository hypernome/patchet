from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException
from api.auth import require_auth
from typing import Dict, List
from contextlib import asynccontextmanager
import random, logging
import time
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BuildingState(BaseModel):
    """Simulated smart building state"""

    def __init__(self):
        self.temperature = 72.0  # Fahrenheit
        self.target_temperature = 72.0
        self.occupancy = 5
        self.hvac_status = "on"
        self.lighting_level = 100  # 0-100%
        self.energy_usage = 45.0  # kW
        self.last_update = time.time()

        # History for demo
        self.action_history: List[Dict] = []

    def update_sensors(self):
        """Simulate sensor reading changes"""
        # Random walk temperature
        self.temperature += random.uniform(-0.5, 0.5)

        # Random occupancy changes
        if random.random() < 0.1:
            self.occupancy = max(0, self.occupancy + random.choice([-1, 1]))

        # Calculate energy based on HVAC and lighting
        base_energy = 20.0
        hvac_energy = 25.0 if self.hvac_status == "on" else 5.0
        lighting_energy = (self.lighting_level / 100) * 10.0

        self.energy_usage = base_energy + hvac_energy + lighting_energy
        self.last_update = time.time()

    def set_hvac(self, target_temp: float, agent_id: str):
        """Control HVAC system"""
        self.target_temperature = target_temp
        self.hvac_status = "on" if abs(target_temp - self.temperature) > 1.0 else "off"

        self.action_history.append(
            {
                "timestamp": time.time(),
                "action": "set_hvac",
                "agent": agent_id,
                "target_temperature": target_temp,
                "hvac_status": self.hvac_status,
            }
        )

    def set_lighting(self, level: int, agent_id: str):
        """Control lighting system"""
        self.lighting_level = max(0, min(100, level))

        self.action_history.append(
            {
                "timestamp": time.time(),
                "action": "set_lighting",
                "agent": agent_id,
                "level": level,
            }
        )

    def get_snapshot(self) -> Dict:
        """Get current building state"""
        return {
            "temperature": round(self.temperature, 1),
            "target_temperature": round(self.target_temperature, 1),
            "occupancy": self.occupancy,
            "hvac_status": self.hvac_status,
            "lighting_level": self.lighting_level,
            "energy_usage": round(self.energy_usage, 1),
            "timestamp": self.last_update,
        }


# Global building state
building = BuildingState()

building_router = APIRouter(prefix="/building")


# Request models
class HVACControl(BaseModel):
    agent_id: str
    target_temperature: float


class LightingControl(BaseModel):
    agent_id: str
    level: int  # 0-100


# Background task to update sensors
@asynccontextmanager
async def lifespan():
    """
    Start background sensor updates.
    """

    async def update_loop():
        while True:
            building.update_sensors()
            await asyncio.sleep(5)  # Update every 5 seconds

    asyncio.create_task(update_loop())
    yield


@building_router.get("/health")
def root():
    """Health check"""
    return {
        "service": "Greentech Workshop Building API",
        "status": "running",
        "version": "1.0.0",
    }


@building_router.get(
    "/sensors",
    dependencies=[
        Depends(
            require_auth(scopes=["read:sensors"], audience="api.localhost.building")
        )
    ],
)
async def read_sensors(agent_id: str):
    """
    Read all building sensors
    Required scope: read:sensors
    """
    logger.info(f"Sensors read by agent: {agent_id}")

    return {"agent": agent_id, "data": building.get_snapshot()}


@building_router.get(
    "/sensors/temperature",
    dependencies=[
        Depends(
            require_auth(scopes=["read:sensors"], audience="api.localhost.building")
        )
    ],
)
async def read_temperature():
    """Read temperature sensor"""
    return {
        "temperature": building.temperature,
        "target": building.target_temperature,
        "unit": "fahrenheit",
    }


@building_router.get(
    "/sensors/occupancy",
    dependencies=[
        Depends(
            require_auth(scopes=["read:sensors"], audience="api.localhost.building")
        )
    ],
)
async def read_occupancy():
    """Read occupancy sensor"""
    return {"occupancy": building.occupancy, "timestamp": building.last_update}


@building_router.post(
    "/hvac/setpoint",
    dependencies=[
        Depends(require_auth(scopes=["write:hvac"], audience="api.localhost.building"))
    ],
)
async def control_hvac(control: HVACControl):
    """
    Control HVAC system
    Required scope: write:hvac
    """
    agent_id = control.agent_id

    # Validate temperature range
    if control.target_temperature < 60 or control.target_temperature > 80:
        raise HTTPException(
            status_code=400, detail="Temperature must be between 60-80°F"
        )

    building.set_hvac(control.target_temperature, agent_id)

    logger.info(
        f"HVAC controlled by agent: {agent_id}, " f"target={control.target_temperature}"
    )

    return {
        "status": "success",
        "agent": agent_id,
        "target_temperature": control.target_temperature,
        "hvac_status": building.hvac_status,
    }


@building_router.post(
    "/lighting/level",
    dependencies=[
        Depends(
            require_auth(scopes=["write:lighting"], audience="api.localhost.building")
        )
    ],
)
async def control_lighting(control: LightingControl):
    """
    Control lighting system
    Required scope: write:lighting
    """
    agent_id = control.agent_id
    building.set_lighting(control.level, agent_id)

    logger.info(f"Lighting controlled by agent: {agent_id}, level={control.level}")

    return {
        "status": "success",
        "agent": agent_id,
        "lighting_level": building.lighting_level,
    }


@building_router.get(
    "/energy",
    dependencies=[
        Depends(require_auth(scopes=["read:data"], audience="api.localhost.building"))
    ],
)
async def read_energy():
    """Read energy usage data"""
    return {"energy_usage_kw": building.energy_usage, "timestamp": building.last_update}


@building_router.get(
    "/history",
    dependencies=[
        Depends(require_auth(scopes=["read:data"], audience="api.localhost.building"))
    ],
)
async def read_history():
    """Get action history"""
    return {"actions": building.action_history[-20:]}  # Last 20 actions

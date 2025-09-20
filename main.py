import os
import asyncio
import json
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
from geopy.distance import geodesic

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "transit-tracker-secret-key-2024")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./transit_tracker.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Security
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# WebSocket Connection Manager for Real-time Updates
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[Dict[str, Any]] = []
        self.driver_locations: Dict[int, Dict] = {}  # Store latest driver locations
    
    async def connect(self, websocket: WebSocket, user_id: int, role: str):
        await websocket.accept()
        self.active_connections.append({
            "websocket": websocket,
            "user_id": user_id,
            "role": role
        })
        print(f"✅ User {user_id} ({role}) connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        for connection in self.active_connections:
            if connection["websocket"] == websocket:
                user_id = connection["user_id"]
                role = connection["role"]
                self.active_connections.remove(connection)
                print(f"❌ User {user_id} ({role}) disconnected. Total: {len(self.active_connections)}")
                break
    
    async def broadcast_to_passengers(self, message: dict):
        """Broadcast message to all passengers"""
        disconnected = []
        sent_count = 0
        
        for connection in self.active_connections:
            if connection["role"] == "passenger":
                try:
                    await connection["websocket"].send_text(json.dumps(message))
                    sent_count += 1
                except:
                    disconnected.append(connection)
        
        # Remove disconnected connections
        for conn in disconnected:
            self.active_connections.remove(conn)
        
        print(f"📡 Broadcasted {message.get('type')} to {sent_count} passengers")
    
    async def update_driver_location(self, driver_id: int, location_data: dict):
        """Store and broadcast driver location update to all passengers"""
        self.driver_locations[driver_id] = location_data
        
        # Broadcast to all passengers immediately
        await self.broadcast_to_passengers({
            "type": "driver_location_update",
            "driver_id": driver_id,
            "bus_id": location_data.get("bus_id"),
            "bus_number": location_data.get("bus_number"),
            "route_name": location_data.get("route_name"),
            "latitude": location_data.get("latitude"),
            "longitude": location_data.get("longitude"),
            "speed": location_data.get("speed", 0),
            "heading": location_data.get("heading", 0),
            "timestamp": location_data.get("timestamp"),
            "capacity": location_data.get("capacity"),
            "passenger_count": location_data.get("passenger_count", 0),
            "crowd_level": location_data.get("crowd_level", "Low")
        })
    
    def get_all_driver_locations(self):
        """Get all current driver locations"""
        return self.driver_locations

# Global connection manager
manager = ConnectionManager()

# Database Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String)  # driver, passenger, admin
    name = Column(String)
    phone = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

class Bus(Base):
    __tablename__ = "buses"
    
    id = Column(Integer, primary_key=True, index=True)
    bus_number = Column(String, unique=True, index=True)
    route_name = Column(String)
    capacity = Column(Integer, default=50)
    driver_id = Column(Integer, ForeignKey("users.id"))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    driver = relationship("User", back_populates="bus")

class Location(Base):
    __tablename__ = "locations"
    
    id = Column(Integer, primary_key=True, index=True)
    bus_id = Column(Integer, ForeignKey("buses.id"))
    driver_id = Column(Integer, ForeignKey("users.id"))
    latitude = Column(Float)
    longitude = Column(Float)
    speed = Column(Float, default=0)
    heading = Column(Float, default=0)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    bus = relationship("Bus")

# Establish relationships
User.bus = relationship("Bus", back_populates="driver")

# Pydantic Models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str
    name: str
    phone: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class LocationUpdate(BaseModel):
    latitude: float
    longitude: float
    speed: Optional[float] = 0
    heading: Optional[float] = 0

class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict

# Helper Functions
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# Application Lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    Base.metadata.create_all(bind=engine)
    
    # Create sample users and buses
    db = SessionLocal()
    try:
        # Create test users if they don't exist
        if not db.query(User).filter(User.email == "driver@test.com").first():
            driver_user = User(
                email="driver@test.com",
                password_hash=get_password_hash("driver123"),
                role="driver",
                name="John Driver"
            )
            db.add(driver_user)
            
        if not db.query(User).filter(User.email == "passenger@test.com").first():
            passenger_user = User(
                email="passenger@test.com",
                password_hash=get_password_hash("passenger123"),
                role="passenger",
                name="Jane Passenger"
            )
            db.add(passenger_user)
            
        if not db.query(User).filter(User.email == "admin@test.com").first():
            admin_user = User(
                email="admin@test.com",
                password_hash=get_password_hash("admin123"),
                role="admin",
                name="Admin User"
            )
            db.add(admin_user)
            
        # Create sample buses if they don't exist
        if not db.query(Bus).first():
            bus1 = Bus(bus_number="BUS-001", route_name="Downtown Express", capacity=50, driver_id=1)
            bus2 = Bus(bus_number="BUS-002", route_name="University Line", capacity=40, driver_id=1)
            db.add(bus1)
            db.add(bus2)
            
        db.commit()
        print("✅ Database initialized with sample data")
        print("🧪 Test credentials:")
        print("   Driver: driver@test.com / driver123")
        print("   Passenger: passenger@test.com / passenger123")
        print("   Admin: admin@test.com / admin123")
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        db.rollback()
    finally:
        db.close()
    
    print("🚀 FastAPI application started successfully!")
    yield
    print("⏹️  Application shutdown")

# FastAPI App
app = FastAPI(
    title="TransitTracker Real-time API",
    description="Real-time Public Transport Tracking API with WebSocket support",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware - IMPORTANT for frontend-backend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication Endpoints
@app.post("/api/login", response_model=Token)
async def login(user: UserLogin, db: Session = Depends(get_db)):
    print(f"🔐 Login attempt: {user.email}")
    
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        print(f"❌ Login failed: {user.email}")
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(db_user.id)}, expires_delta=access_token_expires
    )
    
    print(f"✅ Login successful: {user.email} ({db_user.role})")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": db_user.id,
            "email": db_user.email,
            "role": db_user.role,
            "name": db_user.name
        }
    }

# Driver Location Update Endpoint
@app.post("/api/location")
async def update_location(
    location: LocationUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "driver":
        raise HTTPException(status_code=403, detail="Only drivers can update location")
    
    print(f"📍 Location update from driver {current_user.id}: {location.latitude}, {location.longitude}")
    
    # Get driver's bus
    bus = db.query(Bus).filter(Bus.driver_id == current_user.id).first()
    if not bus:
        print(f"❌ No bus assigned to driver {current_user.id}")
        raise HTTPException(status_code=404, detail="No bus assigned to this driver")
    
    # Save location to database
    timestamp = datetime.utcnow()
    db_location = Location(
        bus_id=bus.id,
        driver_id=current_user.id,
        latitude=location.latitude,
        longitude=location.longitude,
        speed=location.speed,
        heading=location.heading,
        timestamp=timestamp
    )
    db.add(db_location)
    db.commit()
    
    # Prepare location data for broadcasting
    location_data = {
        "bus_id": bus.id,
        "bus_number": bus.bus_number,
        "route_name": bus.route_name,
        "latitude": location.latitude,
        "longitude": location.longitude,
        "speed": location.speed,
        "heading": location.heading,
        "timestamp": timestamp.isoformat(),
        "capacity": bus.capacity,
        "passenger_count": 0,  # Simplified for demo
        "crowd_level": "Low"
    }
    
    # Update location in manager and broadcast to all passengers
    await manager.update_driver_location(current_user.id, location_data)
    
    print(f"✅ Location broadcasted to passengers")
    
    return {
        "status": "success", 
        "message": "Location updated and broadcasted to passengers",
        "data": location_data
    }

# Get Driver Dashboard Data
@app.get("/api/driver/dashboard")
async def get_driver_dashboard(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "driver":
        raise HTTPException(status_code=403, detail="Access denied")
    
    bus = db.query(Bus).filter(Bus.driver_id == current_user.id).first()
    if not bus:
        return {"bus": None, "message": "No bus assigned"}
    
    return {
        "bus": {
            "id": bus.id,
            "number": bus.bus_number,
            "route_name": bus.route_name,
            "capacity": bus.capacity
        },
        "status": "active",
        "passenger_count": 0  # Simplified for demo
    }

# Get Nearby Buses for Passengers
@app.get("/api/buses/nearby")
async def get_nearby_buses(
    lat: float,
    lng: float,
    radius: float = 10.0,
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "passenger":
        raise HTTPException(status_code=403, detail="Access denied")
    
    print(f"🔍 Passenger {current_user.id} requesting nearby buses at {lat}, {lng}")
    
    # Get all current driver locations from manager
    driver_locations = manager.get_all_driver_locations()
    
    nearby_buses = []
    user_location = (lat, lng)
    
    for driver_id, location_data in driver_locations.items():
        try:
            bus_location = (location_data["latitude"], location_data["longitude"])
            distance = geodesic(user_location, bus_location).kilometers
            
            if distance <= radius:
                # Calculate ETA (simplified)
                speed_kmh = location_data.get("speed", 25)  # Default speed
                if speed_kmh <= 0:
                    speed_kmh = 25
                    
                eta_hours = distance / speed_kmh
                eta_minutes = max(int(eta_hours * 60), 1)
                
                nearby_buses.append({
                    "bus_id": location_data["bus_id"],
                    "bus_number": location_data["bus_number"],
                    "route_name": location_data["route_name"],
                    "distance": round(distance, 2),
                    "eta": eta_minutes,
                    "latitude": location_data["latitude"],
                    "longitude": location_data["longitude"],
                    "speed": location_data["speed"],
                    "passenger_count": location_data.get("passenger_count", 0),
                    "capacity": location_data["capacity"],
                    "crowd_level": location_data.get("crowd_level", "Low"),
                    "last_updated": location_data["timestamp"]
                })
        except Exception as e:
            print(f"❌ Error processing location for driver {driver_id}: {e}")
            continue
    
    # Sort by distance
    nearby_buses.sort(key=lambda x: x["distance"])
    
    print(f"✅ Found {len(nearby_buses)} nearby buses for passenger {current_user.id}")
    
    return {"buses": nearby_buses, "total_found": len(nearby_buses)}

# WebSocket Endpoint for Real-time Communication
@app.websocket("/ws/{user_id}/{role}")
async def websocket_endpoint(websocket: WebSocket, user_id: int, role: str):
    await manager.connect(websocket, user_id, role)
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            
            if message.get("type") == "ping":
                await websocket.send_text(json.dumps({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat()
                }))
                
            elif message.get("type") == "request_all_buses" and role == "passenger":
                # Send all current bus locations to passenger
                all_locations = manager.get_all_driver_locations()
                await websocket.send_text(json.dumps({
                    "type": "all_bus_locations",
                    "locations": all_locations,
                    "timestamp": datetime.utcnow().isoformat()
                }))
                print(f"📍 Sent {len(all_locations)} bus locations to passenger {user_id}")
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"❌ WebSocket error for user {user_id}: {e}")
        manager.disconnect(websocket)

# Health Check Endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "active_connections": len(manager.active_connections),
        "active_drivers": len(manager.get_all_driver_locations()),
        "message": "TransitTracker API is running"
    }

# Root Endpoint
@app.get("/")
async def root():
    return {
        "message": "🚌 TransitTracker Real-time API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "websocket": "/ws/{user_id}/{role}"
    }

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting TransitTracker API server...")
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))

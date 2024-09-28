#!/usr/bin/env python3
"""DB module
"""


from sqlalchemy.exc import NoResultFound, InvalidRequestError
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from typing import Optional
from typing import Dict


from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
    """Initialize a new DB instance
    """
    self._engine = create_engine("sqlite:///a.db", echo=True)
    Base.metadata.drop_all(self._engine)
    Base.metadata.create_all(self._engine)
    self.__session: Optional[Session] = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Add a user to the database.
        """
        new_user = User(email=email, hashed_password=hashed_password)

        # Add the new user to the session
        self._session.add(new_user)

        # Commit the transaction to save the user to the database
        self._session.commit()

        # Return the User object
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """Find a user by arbitrary keyword arguments.
        """
        try:
            # Use SQLAlchemy's filter_by to search for the user
            user = self._session.query(User).filter_by(**kwargs).first()

            # If no user is found, raise NoResultFound
            if user is None:
                raise NoResultFound

            return user
        except AttributeError as e:
            # This would occur if invalid attribute names are passed in **kwargs
            raise InvalidRequestError from e
